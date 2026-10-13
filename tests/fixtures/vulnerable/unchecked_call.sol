// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Sender {
    function send(address payable to) external payable {
        to.call{value: msg.value}("");
    }
}
