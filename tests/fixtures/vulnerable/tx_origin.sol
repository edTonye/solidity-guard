// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Wallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        to.transfer(amount);
    }
}
