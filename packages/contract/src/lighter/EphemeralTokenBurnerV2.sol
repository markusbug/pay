// // SPDX-License-Identifier: Apache-2.0
// pragma solidity 0.8.25;

// import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
// import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
// import "./interfaces/ITokenMessengerV2.sol";

// // This contract is deployed, then destroyed again in the same transaction.
// contract EphemeralTokenBurnerV2 {
//     using SafeERC20 for IERC20;

//     address payable private immutable _creator;
//     address private immutable _zklighterRecipient;
//     address immutable _claimContract;

//     constructor(address zklighterRecipient, address claimContract) {
//         _creator = payable(msg.sender);
//         _zklighterRecipient = zklighterRecipient;
//         _claimContract = claimContract;
//     }

//     function rescueMoney(IERC20 token) external {
//         require(msg.sender == _creator, "FCCTP: only creator");

//         uint256 receivedAmount = token.balanceOf(address(this));
//         require(receivedAmount > 0, "FCCTP: insufficient balance received");
//         token.safeTransfer(_zklighterRecipient, receivedAmount);
//         require(token.balanceOf(address(this)) == 0, "FCCTP: leftover tokens");
//     }

//     function transferToCreator(IERC20 token, uint256 amount) external {
//         require(msg.sender == _creator, "FCCTP: only creator");
//         require(amount > 0, "FCCTP: no token to transfer");
//         uint256 balance = token.balanceOf(address(this));
//         require(balance >= amount, "insufficient balance");
//         token.safeTransfer(_creator, amount);
//     }
// }
