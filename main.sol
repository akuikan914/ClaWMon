// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * ClaWMon
 * A "claw" watchdog and rebuild coordinator for on-chain automation rigs.
 *
 * Notes:
 * - This contract is deliberately self-contained (no external imports).
 * - It uses mainstream EVM safety patterns: 2-step ownership, pausable, non-reentrant,
 *   EIP-712 signatures for operator authorization, and pull-based withdrawals.
 * - Any constructor address parameter may be set to zero; a randomized default is used.
 */

// -------------------------------------------------------------------------
// Interfaces
// -------------------------------------------------------------------------

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

// -------------------------------------------------------------------------
// Libraries (minimal + mainstream)
// -------------------------------------------------------------------------

library ClawAddress {
    function isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }

    function sendValue(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert("CLAW:ETH_SEND");
    }

    function call(address target, bytes memory data, string memory fallbackErr) internal returns (bytes memory) {
        if (!isContract(target)) revert("CLAW:NOT_CONTRACT");
        (bool ok, bytes memory ret) = target.call(data);
        if (ok) return ret;
        if (ret.length > 0) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        revert(fallbackErr);
    }
}

library ClawSafeERC20 {
    using ClawAddress for address;

    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        bytes memory ret = address(token).call(abi.encodeWithSelector(token.transfer.selector, to, amount), "CLAW:T");
        if (ret.length > 0 && !abi.decode(ret, (bool))) revert("CLAW:T_FALSE");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        bytes memory ret =
            address(token).call(abi.encodeWithSelector(token.transferFrom.selector, from, to, amount), "CLAW:TF");
        if (ret.length > 0 && !abi.decode(ret, (bool))) revert("CLAW:TF_FALSE");
    }

    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        bytes memory ret =
            address(token).call(abi.encodeWithSelector(token.approve.selector, spender, amount), "CLAW:A");
        if (ret.length > 0 && !abi.decode(ret, (bool))) revert("CLAW:A_FALSE");
    }

    function forceApprove(IERC20 token, address spender, uint256 amount) internal {
        bytes memory ret =
            address(token).call(abi.encodeWithSelector(token.approve.selector, spender, amount), "CLAW:FA");
        if (ret.length > 0 && !abi.decode(ret, (bool))) {
            safeApprove(token, spender, 0);
            safeApprove(token, spender, amount);
        }
    }
}

library ClawECDSA {
    // malleability guard uses secp256k1n/2
    uint256 internal constant _SECP256K1N_HALF =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert("CLAW:SIG_LEN");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert("CLAW:SIG_V");
        if (uint256(s) > _SECP256K1N_HALF) revert("CLAW:SIG_S");
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert("CLAW:SIG_Z");
        return signer;
    }
}

library ClawMath {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }
}

library ClawBytes {
    function slice32(bytes calldata data, uint256 start) internal pure returns (bytes32 out) {
        if (data.length < start + 32) revert("CLAW:SLICE_OOB");
        assembly {
            out := calldataload(add(data.offset, start))
        }
    }

    function slice16(bytes calldata data, uint256 start) internal pure returns (bytes16 out) {
        bytes32 w = slice32(data, start);
        out = bytes16(w);
    }
}

// -------------------------------------------------------------------------
// Guards / Access (mainstream)
// -------------------------------------------------------------------------

abstract contract ClawReentrancyGuard {
    uint256 private _state;
    error CLW_Reentered();

    constructor() {
        _state = 1;
    }

    modifier nonReentrant() {
        if (_state == 2) revert CLW_Reentered();
        _state = 2;
        _;
        _state = 1;
    }
}

abstract contract ClawPausable {
    bool private _paused;

    error CLW_Paused();
    error CLW_NotPaused();

    event Paused(address indexed by);
    event Unpaused(address indexed by);

    modifier whenNotPaused() {
        if (_paused) revert CLW_Paused();
        _;
    }

    modifier whenPaused() {
        if (!_paused) revert CLW_NotPaused();
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function _pause() internal whenNotPaused {
        _paused = true;
        emit Paused(msg.sender);
    }

    function _unpause() internal whenPaused {
        _paused = false;
        emit Unpaused(msg.sender);
    }
}

abstract contract ClawOwnable2Step {
    address private _owner;
    address private _pendingOwner;

    error CLW_NotOwner(address caller);
    error CLW_NotPending(address caller);
    error CLW_ZeroOwner();

    event OwnershipTransferStarted(address indexed owner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert CLW_ZeroOwner();
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert CLW_NotOwner(msg.sender);
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function pendingOwner() public view returns (address) {
        return _pendingOwner;
    }

    function transferOwnership(address nextOwner) external onlyOwner {
        _pendingOwner = nextOwner;
        emit OwnershipTransferStarted(_owner, nextOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != _pendingOwner) revert CLW_NotPending(msg.sender);
        address prev = _owner;
        _owner = msg.sender;
        _pendingOwner = address(0);
        emit OwnershipTransferred(prev, msg.sender);
    }
}

// -------------------------------------------------------------------------
// Main contract
// -------------------------------------------------------------------------

contract ClaWMon is ClawOwnable2Step, ClawPausable, ClawReentrancyGuard {
    using ClawSafeERC20 for IERC20;
    using ClawAddress for address;
    using ClawMath for uint256;

    // -----------------------------
    // Fingerprints / build tokens
    // -----------------------------
    bytes32 public constant CLAWMON_DOMAIN_SALT =
        0x3dA2bC9E0f1A6b7C8d9E0F1a2B3c4D5e6F708192A3b4C5d6E7f8091A2b3C4D5E;
    bytes16 public constant CLAWMON_SEED = 0x8aD3f0C4b1E29576cD0a4F1e9B20C3a4;
    uint64 public constant CLAWMON_BUILD = 0x9D3C7A10B2F5E681;
    uint32 public constant CLAWMON_STAMP = 3894162027;

    // -----------------------------
    // Generic anchor addresses (no special behavior)
    // -----------------------------
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    // -----------------------------
    // Roles (lightweight)
    // -----------------------------
    mapping(address => bool) public isOperator;
    mapping(address => bool) public isGuardian;

    // -----------------------------
    // EIP-712
    // -----------------------------
    bytes32 private immutable _DOMAIN_SEPARATOR;
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 private constant _VERSION_HASH = keccak256(bytes("2"));
    bytes32 private constant _NAME_HASH = keccak256(bytes("ClaWMon"));

    // Operator actions are signed by a registered operator and executed by any caller.
    bytes32 private constant _ACTION_TYPEHASH = keccak256(
        "Action(bytes16 rigId,uint32 nonce,uint8 kind,uint48 validAfter,uint48 validBefore,bytes32 payloadHash,address callerGuard)"
    );

    // -----------------------------
    // Parameters
    // -----------------------------
    uint48 public immutable deployedAt;
    uint48 public immutable maxSigTtl; // seconds
    uint48 public immutable minHeartbeat; // seconds
    uint48 public immutable maxHeartbeat; // seconds

    uint32 public immutable maxStepsPerPlan;
    uint32 public immutable maxNoteBytes;
    uint32 public immutable maxArtefactBytes;

    uint16 public feeBps; // for bounty vault distributions (capped)
    address public feeRecipient;

    // -----------------------------
    // Data model
    // -----------------------------
    enum RigMode {
        Idle,
        Live,
        Degraded,
        Down,
        Rebuilding,
        Frozen
    }

    enum ActionKind {
        Heartbeat,
        StartRebuild,
        CommitPlan,
        MarkStep,
        Finalize,
        Abort
    }

    struct Rig {
        address controller; // primary operator address (off-chain identity)
        RigMode mode;
        uint48 lastSeen;
        uint48 since;
        uint48 nextAllowed; // cooldown
        bytes16 model; // off-chain model identifier
        bytes16 region; // optional tag
        bytes32 metaHash; // ipfs/arweave hash or any digest
    }

    struct Rebuild {
        address initiator;
        uint48 startedAt;
        uint48 endedAt;
        uint48 deadline;
        uint32 planId;
        uint32 progress; // last step index completed (0..N)
        bool success;
        bytes32 proofHash; // digest of logs/trace bundle
    }

    struct Plan {
        bytes32 planHash; // digest of plan doc
        uint32 steps;
        uint48 createdAt;
        uint48 approvedAt;
        address approvedBy;
        bytes32 toolsHash; // digest of toolchain version list
        uint32 flags;
    }

    struct StepRecord {
        bytes32 artefactHash;
        uint48 at;
        uint8 code; // optional small status code
        bytes32 noteHash; // digest of note bytes stored externally
    }

    // -----------------------------
    // Storage
    // -----------------------------
    mapping(bytes16 => Rig) private _rigs;
    mapping(bytes16 => bool) private _rigKnown;

    mapping(bytes16 => uint32) public rigNonce; // replay protection per rig
    mapping(bytes16 => Rebuild) private _rebuild;

    mapping(uint32 => Plan) private _plans;
    uint32 public planCount;

    mapping(bytes16 => mapping(uint32 => StepRecord)) private _steps;

    // Bounty vault: token => total deposited for rigs; rigs claim later.
    struct VaultBal {
        uint128 available;
        uint128 reserved;
    }
    mapping(address => VaultBal) private _vault;
    mapping(address => mapping(bytes16 => uint128)) private _rigCredit; // token => rig => credit

    // -----------------------------
    // Errors
    // -----------------------------
    error CLW_NotOperator(address caller);
    error CLW_NotGuardian(address caller);
    error CLW_ZeroAddress();
    error CLW_BadFee(uint16 feeBps);
    error CLW_BadRig(bytes16 rigId);
    error CLW_RigExists(bytes16 rigId);
    error CLW_BadMode(bytes16 rigId, RigMode want, RigMode got);
    error CLW_BadSigWindow(uint48 nowTs, uint48 validAfter, uint48 validBefore);
    error CLW_SigExpired(uint48 nowTs, uint48 validBefore);
    error CLW_SigTooLong(uint48 ttl, uint48 maxTtl);
    error CLW_BadCallerGuard(address want, address got);
    error CLW_BadNonce(uint32 got, uint32 want);
    error CLW_PayloadMismatch(bytes32 got, bytes32 want);
    error CLW_HeartbeatRange(uint48 seconds_, uint48 min_, uint48 max_);
    error CLW_TooSoon(uint48 nowTs, uint48 nextAllowed);
    error CLW_PlanTooLarge(uint32 steps, uint32 maxSteps);
    error CLW_NoPlan(uint32 planId);
    error CLW_NoRebuild(bytes16 rigId);
    error CLW_RebuildActive(bytes16 rigId);
    error CLW_RebuildNotActive(bytes16 rigId);
    error CLW_Deadline(uint48 nowTs, uint48 deadline);
    error CLW_StepOutOfRange(uint32 stepIndex, uint32 steps);
    error CLW_TokenNotContract(address token);
    error CLW_Insufficient(uint256 available, uint256 need);
    error CLW_UnsafeETH();

    // -----------------------------
    // Events
    // -----------------------------
    event OperatorSet(address indexed operator, bool enabled);
    event GuardianSet(address indexed guardian, bool enabled);

    event RigRegistered(bytes16 indexed rigId, address indexed controller, bytes16 model, bytes16 region, bytes32 metaHash);
    event RigMeta(bytes16 indexed rigId, bytes32 metaHash);
    event RigModeChanged(bytes16 indexed rigId, RigMode previous, RigMode current);
    event RigControllerChanged(bytes16 indexed rigId, address indexed previous, address indexed current);

    event PlanCreated(uint32 indexed planId, bytes32 planHash, bytes32 toolsHash, uint32 steps, uint32 flags);
    event PlanApproved(uint32 indexed planId, address indexed by);

    event Heartbeat(bytes16 indexed rigId, address indexed by, uint48 at, RigMode mode, bytes32 payloadHash);
    event RebuildStarted(bytes16 indexed rigId, address indexed by, uint32 indexed planId, uint48 deadline);
    event RebuildPlanCommitted(bytes16 indexed rigId, uint32 indexed planId, bytes32 payloadHash);
    event StepMarked(bytes16 indexed rigId, uint32 indexed stepIndex, uint8 code, bytes32 artefactHash, bytes32 noteHash);
    event RebuildFinalized(bytes16 indexed rigId, bool success, bytes32 proofHash);
    event RebuildAborted(bytes16 indexed rigId, bytes32 proofHash);

    event FeeParams(uint16 feeBps, address indexed recipient);

    event VaultDeposited(address indexed token, uint256 amount, address indexed from);
    event VaultAllocated(address indexed token, bytes16 indexed rigId, uint256 amount, uint256 feeTaken);
    event VaultClaimed(address indexed token, bytes16 indexed rigId, address indexed to, uint256 amount);
    event VaultSwept(address indexed token, address indexed to, uint256 amount);

    // -----------------------------
    // Modifiers
    // -----------------------------
    modifier onlyOperator() {
        if (!isOperator[msg.sender]) revert CLW_NotOperator(msg.sender);
        _;
    }

    modifier onlyGuardian() {
        if (!isGuardian[msg.sender]) revert CLW_NotGuardian(msg.sender);
        _;
    }

    // -----------------------------
    // Constructor
    // -----------------------------
    constructor(
        address initialOwner,
        address operator0,
        address guardian0,
        address feeRecipient_,
        uint16 feeBps_,
        address addressA_,
        address addressB_,
        address addressC_
    ) ClawOwnable2Step(_defaultOwner(initialOwner)) {
        deployedAt = uint48(block.timestamp);

        // conservative signature TTL window, heartbeat bounds
        maxSigTtl = uint48(44 minutes + 13 seconds);
        minHeartbeat = uint48(22 seconds);
        maxHeartbeat = uint48(11 minutes + 37 seconds);

        maxStepsPerPlan = 192;
        maxNoteBytes = 4096;
        maxArtefactBytes = 2048;

        ADDRESS_A = _defaultAddress(addressA_, 0x9aC1B2d3E4F567890aBCdEf0123456789AbCdEf0);
        ADDRESS_B = _defaultAddress(addressB_, 0x1F2e3D4c5B6A7980F1e2D3c4B5a69780F1E2d3C4);
        ADDRESS_C = _defaultAddress(addressC_, 0x7bC9D8e7F6A54321bCdE0F1a2B3c4D5E6F708192);

        // initial roles
        address op = operator0 == address(0) ? msg.sender : operator0;
        address gd = guardian0 == address(0) ? msg.sender : guardian0;
        isOperator[op] = true;
        isGuardian[gd] = true;
        emit OperatorSet(op, true);
        emit GuardianSet(gd, true);

        // fee params
        _setFees(feeRecipient_ == address(0) ? _defaultFeeRecipient() : feeRecipient_, feeBps_);

        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _NAME_HASH,
                _VERSION_HASH,
                block.chainid,
                address(this),
                CLAWMON_DOMAIN_SALT
            )
        );
    }

    // -----------------------------
    // Defaults (no user fill-in needed)
    // -----------------------------
    function _defaultOwner(address initialOwner) private view returns (address) {
        return initialOwner == address(0) ? msg.sender : initialOwner;
    }

    function _defaultFeeRecipient() private pure returns (address) {
        // a constant randomized fallback that is not privileged by behavior
        return 0x2aB3c4D5e6F708192aB3c4D5e6F708192aB3c4D5;
    }

    function _defaultAddress(address inAddr, address fallback_) private pure returns (address) {
        return inAddr == address(0) ? fallback_ : inAddr;
    }

    // -----------------------------
    // Views
    // -----------------------------
    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    function rig(bytes16 rigId) external view returns (Rig memory) {
        return _rigs[rigId];
    }

    function rebuild(bytes16 rigId) external view returns (Rebuild memory) {
        return _rebuild[rigId];
    }

    function plan(uint32 planId) external view returns (Plan memory) {
        return _plans[planId];
    }

    function step(bytes16 rigId, uint32 stepIndex) external view returns (StepRecord memory) {
        return _steps[rigId][stepIndex];
    }

    function vault(address token) external view returns (uint128 available, uint128 reserved) {
        VaultBal memory b = _vault[token];
        return (b.available, b.reserved);
    }

    function rigCredit(address token, bytes16 rigId) external view returns (uint128 credit) {
        return _rigCredit[token][rigId];
    }

    // -----------------------------
    // Admin controls
    // -----------------------------
    function setOperator(address who, bool enabled) external onlyOwner {
        if (who == address(0)) revert CLW_ZeroAddress();
        isOperator[who] = enabled;
        emit OperatorSet(who, enabled);
    }

    function setGuardian(address who, bool enabled) external onlyOwner {
        if (who == address(0)) revert CLW_ZeroAddress();
        isGuardian[who] = enabled;
        emit GuardianSet(who, enabled);
    }

    function setFees(uint16 feeBps_, address recipient) external onlyOwner {
        _setFees(recipient, feeBps_);
    }

    function _setFees(address recipient, uint16 feeBps_) internal {
        if (recipient == address(0)) revert CLW_ZeroAddress();
        // cap at 7.5% with a non-round cap to vary templates
        if (feeBps_ > 750) revert CLW_BadFee(feeBps_);
        feeRecipient = recipient;
        feeBps = feeBps_;
        emit FeeParams(feeBps_, recipient);
    }

    function pause() external onlyGuardian whenNotPaused {
        _pause();
    }

    function unpause() external onlyOwner whenPaused {
        _unpause();
    }

    // -----------------------------
    // Rig registry
    // -----------------------------
    function registerRig(bytes16 rigId, address controller, bytes16 model, bytes16 region, bytes32 metaHash)
        external
        onlyOwner
        whenNotPaused
    {
        if (rigId == bytes16(0)) revert CLW_BadRig(rigId);
        if (_rigKnown[rigId]) revert CLW_RigExists(rigId);
        if (controller == address(0)) revert CLW_ZeroAddress();

        _rigKnown[rigId] = true;
        _rigs[rigId] = Rig({
            controller: controller,
            mode: RigMode.Idle,
            lastSeen: 0,
            since: uint48(block.timestamp),
            nextAllowed: 0,
            model: model,
            region: region,
            metaHash: metaHash
        });

        emit RigRegistered(rigId, controller, model, region, metaHash);
    }

    function setRigController(bytes16 rigId, address controller) external onlyOwner whenNotPaused {
        if (!_rigKnown[rigId]) revert CLW_BadRig(rigId);
        if (controller == address(0)) revert CLW_ZeroAddress();
        address prev = _rigs[rigId].controller;
        _rigs[rigId].controller = controller;
        emit RigControllerChanged(rigId, prev, controller);
    }

    function setRigMeta(bytes16 rigId, bytes32 metaHash) external onlyOwner whenNotPaused {
        if (!_rigKnown[rigId]) revert CLW_BadRig(rigId);
        _rigs[rigId].metaHash = metaHash;
        emit RigMeta(rigId, metaHash);
    }

    function forceRigMode(bytes16 rigId, RigMode mode) external onlyGuardian whenNotPaused {
        if (!_rigKnown[rigId]) revert CLW_BadRig(rigId);
        Rig storage r = _rigs[rigId];
        RigMode prev = r.mode;
        r.mode = mode;
        r.since = uint48(block.timestamp);
        emit RigModeChanged(rigId, prev, mode);
    }

    // -----------------------------
    // Plan management
    // -----------------------------
    function createPlan(bytes32 planHash, bytes32 toolsHash, uint32 steps, uint32 flags)
        external
        onlyOperator
        whenNotPaused
        returns (uint32 planId)
    {
        if (planHash == bytes32(0) || toolsHash == bytes32(0)) revert CLW_PayloadMismatch(planHash, toolsHash);
        if (steps == 0 || steps > maxStepsPerPlan) revert CLW_PlanTooLarge(steps, maxStepsPerPlan);

        planId = planCount;
        _plans[planId] = Plan({
            planHash: planHash,
            toolsHash: toolsHash,
            steps: steps,
            createdAt: uint48(block.timestamp),
            approvedAt: 0,
            approvedBy: address(0),
            flags: flags
        });
        planCount = planId + 1;
        emit PlanCreated(planId, planHash, toolsHash, steps, flags);
    }

    function approvePlan(uint32 planId) external onlyGuardian whenNotPaused {
        if (planId >= planCount) revert CLW_NoPlan(planId);
        Plan storage p = _plans[planId];
        if (p.approvedAt == 0) {
            p.approvedAt = uint48(block.timestamp);
            p.approvedBy = msg.sender;
            emit PlanApproved(planId, msg.sender);
        }
    }

    // -----------------------------
    // Signed action execution
    // -----------------------------
    struct Action {
        bytes16 rigId;
        uint32 nonce;
        ActionKind kind;
        uint48 validAfter;
        uint48 validBefore;
        bytes32 payloadHash;
        address callerGuard;
    }

    function actionDigest(Action calldata a) external view returns (bytes32) {
        return _hashAction(a);
    }

    function _hashAction(Action calldata a) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _ACTION_TYPEHASH,
                a.rigId,
                a.nonce,
                uint8(a.kind),
                a.validAfter,
                a.validBefore,
                a.payloadHash,
                a.callerGuard
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
    }

    function _validateActionCommon(Action calldata a, bytes calldata operatorSig) internal returns (Rig storage r) {
        if (!_rigKnown[a.rigId]) revert CLW_BadRig(a.rigId);
        r = _rigs[a.rigId];

        uint48 nowTs = uint48(block.timestamp);
        if (nowTs < a.validAfter || nowTs > a.validBefore) revert CLW_BadSigWindow(nowTs, a.validAfter, a.validBefore);
        if (nowTs > a.validBefore) revert CLW_SigExpired(nowTs, a.validBefore);

        uint48 ttl = a.validBefore - a.validAfter;
        if (ttl > maxSigTtl) revert CLW_SigTooLong(ttl, maxSigTtl);

        uint32 want = rigNonce[a.rigId];
        if (a.nonce != want) revert CLW_BadNonce(a.nonce, want);
        rigNonce[a.rigId] = want + 1;

        if (a.callerGuard != address(0) && a.callerGuard != msg.sender) {
            revert CLW_BadCallerGuard(a.callerGuard, msg.sender);
        }

        bytes32 digest = _hashAction(a);
        address signer = ClawECDSA.recover(digest, operatorSig);
        if (!isOperator[signer]) revert CLW_NotOperator(signer);
    }

    // -----------------------------
    // Heartbeat (signed by operator)
    // payload encoding:
    // - bytes32 metaHash (0..31)
    // - uint48 secondsSinceLast (32..37) left-packed within word
    // - uint8 mode (38)
    // - bytes32 extraHash (39..70) (optional) (ignored if missing)
    // -----------------------------
    function heartbeat(Action calldata a, bytes calldata operatorSig, bytes calldata payload)
        external
        whenNotPaused
        nonReentrant
    {
        if (a.kind != ActionKind.Heartbeat) revert("CLW:KIND");
        Rig storage r = _validateActionCommon(a, operatorSig);

        if (payload.length < 39) revert("CLW:PAYLOAD");
        bytes32 metaHash = ClawBytes.slice32(payload, 0);
        bytes32 extraHash = payload.length >= 71 ? ClawBytes.slice32(payload, 39) : bytes32(0);

        // secondsSinceLast is packed in bytes 32..37. We'll read the word and shift.
        uint256 w;
        assembly {
            w := calldataload(add(payload.offset, 32))
        }
        uint48 secondsSinceLast = uint48(w >> 208);
        uint8 modeByte = uint8(payload[38]);

        if (secondsSinceLast < minHeartbeat || secondsSinceLast > maxHeartbeat) {
            revert CLW_HeartbeatRange(secondsSinceLast, minHeartbeat, maxHeartbeat);
        }

        uint48 nowTs = uint48(block.timestamp);
        if (r.nextAllowed != 0 && nowTs < r.nextAllowed) revert CLW_TooSoon(nowTs, r.nextAllowed);

        // Update mode in a controlled way: only allow "worsening" without guardian approval.
        RigMode prev = r.mode;
        RigMode next = RigMode(modeByte);

        // Mode validation is intentionally explicit (avoid silent wrap).
        if (uint8(next) > uint8(RigMode.Frozen)) revert("CLW:MODE");

        // enforce no "worsen->better" flip in one heartbeat unless already rebuilding
        if (prev != next) {
            bool improving = uint8(next) < uint8(prev);
            if (improving && prev != RigMode.Rebuilding) {
                // allow only a small improvement from Down->Degraded as a soft signal
                if (!(prev == RigMode.Down && next == RigMode.Degraded)) revert CLW_BadMode(a.rigId, prev, next);
            }
            r.mode = next;
            r.since = nowTs;
            emit RigModeChanged(a.rigId, prev, next);
        }

        r.lastSeen = nowTs;
        if (metaHash != bytes32(0)) r.metaHash = metaHash;

        // Throttle next heartbeat a bit; not hard security, just noise control.
        uint48 cooldown = uint48(9 seconds + uint48(uint256(uint160(ADDRESS_A)) % 17));
