// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract Legacy {
    uint256 public count;

    function inc() external {
        count += 1;
    }
}
