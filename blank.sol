// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title tGt Random Reward Distributor (Secure Rolling Pool, 10+ Years)
 * @notice
 *  - Uses off-chain Merkle trees to allocate rewards per cycle
 *  - Authorized rootSetter (e.g., multisig / DAO) sets Merkle roots
 *  - Each cycle has a limited claim window (cycle end + 60 days)
 *  - Unclaimed tokens remain in the pool and can be reallocated in future cycles
 *  - Program is planned for 10 years, but continues AFTER 10 years
 *    until remainingPool() <= MIN_REMAINING
 */
contract TGtRandomDistributor is ReentrancyGuard {
    // -----------------------------------------------------------------------
    // Immutable Configuration
    // -----------------------------------------------------------------------

    IERC20 public immutable rewardToken;    // tGt token address
    address public immutable rootSetter;    // Authorized Merkle root setter

    uint256 public immutable totalPool;     // Total tokens logically allocated to this program
    uint256 public immutable cycleDuration; // Duration of each cycle (e.g., 30 days)
    uint256 public immutable startTime;     // Program start timestamp

    // Planned program duration: 10 years
    uint256 public constant PROGRAM_DURATION = 365 days * 10;

    // Time allowed to claim after a cycle ends (2 months)
    uint256 public constant CLAIM_WINDOW = 60 days;

    // Time allowed to set the Merkle root after a cycle ends (14 days)
    uint256 public constant ROOT_SETTING_WINDOW = 14 days;

    // Minimum amount of tokens that must remain in the contract forever.
    // The program continues (even after 10 years) until remainingPool() <= MIN_REMAINING.
    uint256 public constant MIN_REMAINING = 50_000 * 1e18;

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    // cycle => Merkle root
    mapping(uint256 => bytes32) public merkleRoots;

    // cycle => user => claimed?
    mapping(uint256 => mapping(address => bool)) public claimed;

    // cycle => total claimed amount in that cycle (for analytics)
    mapping(uint256 => uint256) public claimedInCycle;

    // Total amount claimed across all cycles (global accounting)
    uint256 public totalClaimed;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event MerkleRootSet(uint256 indexed cycle, bytes32 merkleRoot, address indexed setter);
    event Claimed(uint256 indexed cycle, address indexed account, uint256 amount);

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(
        address _rewardToken,
        address _rootSetter,
        uint256 _startTime,
        uint256 _cycleDuration,
        uint256 _totalPool
    ) {
        require(_rewardToken != address(0), "Invalid token address");
        require(_rootSetter != address(0), "Invalid rootSetter");
        require(_startTime > block.timestamp, "Start time must be in the future");
        require(_cycleDuration > 0, "Invalid cycle duration");
        // Program must have more than MIN_REMAINING, otherwise it would never start
        require(_totalPool > MIN_REMAINING, "Total pool must exceed MIN_REMAINING");

        rewardToken = IERC20(_rewardToken);
        rootSetter = _rootSetter;
        startTime = _startTime;
        cycleDuration = _cycleDuration;
        totalPool = _totalPool;
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    /// @notice Returns the current cycle index (0-based, unbounded upwards)
    function currentCycle() public view returns (uint256) {
        if (block.timestamp < startTime) {
            return 0;
        }
        uint256 elapsed = block.timestamp - startTime;
        return elapsed / cycleDuration;
    }

    /// @notice Returns the start timestamp of a given cycle
    function cycleStartTime(uint256 cycle) public view returns (uint256) {
        return startTime + cycle * cycleDuration;
    }

    /// @notice Returns the end timestamp of a given cycle
    function cycleEndTime(uint256 cycle) public view returns (uint256) {
        return startTime + (cycle + 1) * cycleDuration;
    }

    /// @notice Returns the planned "10-year end time" of the program.
    /// @dev Distribution DOES NOT stop automatically at this time.
    ///      It continues as long as remainingDistributable() > 0.
    function plannedEndTime() public view returns (uint256) {
        return startTime + PROGRAM_DURATION;
    }

    /// @notice Returns how many tokens (logically) remain from the initial pool.
    function remainingPool() public view returns (uint256) {
        if (totalClaimed >= totalPool) {
            return 0;
        }
        return totalPool - totalClaimed;
    }

    /**
     * @notice Returns how many tokens are still distributable.
     * @dev
     *  - When remainingPool() <= MIN_REMAINING, this returns 0
     *  - The program continues beyond 10 years until this becomes 0
     */
    function remainingDistributable() public view returns (uint256) {
        uint256 remaining = remainingPool();
        if (remaining <= MIN_REMAINING) {
            return 0;
        }
        return remaining - MIN_REMAINING;
    }

    /// @notice Returns the actual token balance currently held by this contract.
    function contractBalance() external view returns (uint256) {
        return rewardToken.balanceOf(address(this));
    }

    /// @notice Returns true if there are no distributable tokens left.
    function isProgramFinished() external view returns (bool) {
        return remainingDistributable() == 0;
    }

    /// @notice Returns true if `account` has claimed for `cycle`.
    function hasClaimed(uint256 cycle, address account) external view returns (bool) {
        return claimed[cycle][account];
    }

    // -----------------------------------------------------------------------
    // Merkle Root Management (Authorized)
    // -----------------------------------------------------------------------

    /**
     * @notice Sets the Merkle root for a given cycle.
     * @dev
     *  - Only the authorized rootSetter can call this
     *  - Root can only be set once per cycle
     *  - Root must be set during the cycle or up to ROOT_SETTING_WINDOW after it ends
     *  - This logic continues beyond 10 years; cycles are not capped by time.
     */
    function setMerkleRoot(uint256 cycle, bytes32 merkleRoot) external {
        require(msg.sender == rootSetter, "Only rootSetter");
        require(merkleRoot != bytes32(0), "Empty root");
        require(merkleRoots[cycle] == bytes32(0), "Root already set");

        uint256 cStart = cycleStartTime(cycle);
        uint256 cEnd = cycleEndTime(cycle);

        // Must be a current or past cycle
        require(block.timestamp >= cStart, "Cycle not started");
        // Root must be set no later than ROOT_SETTING_WINDOW after cycle end
        require(block.timestamp <= cEnd + ROOT_SETTING_WINDOW, "Root setting window closed");

        merkleRoots[cycle] = merkleRoot;
        emit MerkleRootSet(cycle, merkleRoot, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Claim Logic
    // -----------------------------------------------------------------------

    /**
     * @notice Claims the allocated amount for msg.sender in a given cycle.
     * @param cycle        Cycle index
     * @param amount       Amount allocated to msg.sender (from off-chain snapshot)
     * @param merkleProof  Merkle proof proving (msg.sender, amount) is in the tree
     */
    function claim(
        uint256 cycle,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external nonReentrant {
        require(amount > 0, "Zero amount");
        require(!claimed[cycle][msg.sender], "Already claimed");

        bytes32 root = merkleRoots[cycle];
        require(root != bytes32(0), "Merkle root not set");

        // Enforce claim window: up to CLAIM_WINDOW after cycle end
        require(
            block.timestamp <= cycleEndTime(cycle) + CLAIM_WINDOW,
            "Claim window closed"
        );

        // Ensure the global program still has distributable tokens
        uint256 distributable = remainingDistributable();
        require(distributable > 0, "Program finished");
        require(amount <= distributable, "Exceeds remaining distributable");

        // Verify Merkle proof: leaf = keccak256(abi.encodePacked(account, amount))
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(
            MerkleProof.verifyCalldata(merkleProof, root, leaf),
            "Invalid Merkle proof"
        );

        // Update global accounting and enforce totalPool ceiling
        uint256 newTotalClaimed = totalClaimed + amount;
        require(newTotalClaimed <= totalPool, "Exceeds total pool");

        // Effects
        claimed[cycle][msg.sender] = true;
        claimedInCycle[cycle] += amount;
        totalClaimed = newTotalClaimed;

        // Interaction
        require(rewardToken.transfer(msg.sender, amount), "Transfer failed");

        emit Claimed(cycle, msg.sender, amount);
    }
}
