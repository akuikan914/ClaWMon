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
