// // SPDX-License-Identifier: Apache-2.0
// pragma solidity 0.8.25;

// import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
// import "./EphemeralTokenBurnerV2.sol";
// import "@openzeppelin/contracts/utils/math/SafeCast.sol";
// import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

// import "./interfaces/IZkLighter.sol";
// import "./interfaces/IMessageTransmitterV2.sol";

// contract FastCCTPV2 {
//   using SafeERC20 for IERC20;

//   uint16 private constant NONCE_INDEX = 12;
//   uint16 private constant AMOUNT_INDEX = 216;
//   uint16 private constant FEE_EXECUTED_INDEX = 312;
//   uint16 private constant HOOK_DATA_INDEX = 376;
//   uint32 private constant FEE_DENOMINATOR = 10_000_000;

//   uint48 public constant NIL_ACCOUNT_INDEX = 2 ** 48 - 1;

//   struct IntentParams {
//     address deployer;
//     address zklighterRecipient;
//     address claimContract;
//   }

//   struct HookData {
//     address[] senders;
//     uint256[] balances;
//   }

//   address immutable public messageTransmitter; // Address of Circle's MessageTransmitter
//   address immutable public zklighterProxy; // Address of zklighter proxy
//   IERC20 immutable public usdcToken;

//   address public governor;
//   mapping(address => bool) public validators;

//   event DepositClaimed(address claimerAddress, bytes32 nonce);

//   constructor(address _usdcToken, address _messageTransmitter, address _zklighterProxy, address _governor) {
//     usdcToken = IERC20(_usdcToken);
//     messageTransmitter = _messageTransmitter;
//     zklighterProxy = _zklighterProxy;
//     governor = _governor;
//     usdcToken.approve(zklighterProxy, type(uint256).max);
//   }

//   // Function to process the Circle attestations
//   function batchClaimTransfers(bytes[] calldata allMessages, bytes[] calldata attestations) external {
//     uint256 messageLen = allMessages.length;
//     require(messageLen == attestations.length, "Invalid input length");

//     bool _isValidator = isValidator(msg.sender);
//     for (uint256 i = 0; i < messageLen; ++i) {
//       bytes calldata message = allMessages[i];
//       bytes calldata hookData = message[HOOK_DATA_INDEX:];
//       bytes calldata attestation = attestations[i];

//       (address[] memory senders, uint256[] memory balances, uint256 feeTicker, uint256 feeAddition) = abi.decode(
//         hookData,
//         (address[], uint256[], uint256, uint256)
//       );

//       uint256 senderLen = senders.length;
//       require(senderLen == balances.length, "Invalid hook data length");

//       bool success = IMessageTransmitterV2(messageTransmitter).receiveMessage(message, attestation);
//       require(success, "Message processing failed");

//       bytes32 nonce = abi.decode(message[NONCE_INDEX:NONCE_INDEX + 32], (bytes32));
//       uint256 burnedAmount = abi.decode(message[AMOUNT_INDEX:AMOUNT_INDEX + 32], (uint256));
//       uint256 feeExecuted = abi.decode(message[FEE_EXECUTED_INDEX:FEE_EXECUTED_INDEX + 32], (uint256));
//       uint256 receivedAmount = burnedAmount - feeExecuted;

//       uint256 totalBalances = 0;
//       uint64[] memory amounts = new uint64[](senderLen);

//       for (uint256 j = 0; j < senderLen; ++j) {
//         uint256 depositAmount = _calculateDepositAmount(balances[j], feeTicker, feeAddition);
//         totalBalances += balances[j];
//         amounts[j] = SafeCast.toUint64(depositAmount);
//       }

//       if (!_isValidator && receivedAmount < totalBalances) {
//         usdcToken.safeTransferFrom(msg.sender, address(this), totalBalances - receivedAmount);
//       }

//       uint48[] memory accountIndexes = new uint48[](senderLen);
//       for (uint256 j = 0; j < senderLen; ++j) {
//         accountIndexes[j] = NIL_ACCOUNT_INDEX; // to use default account index for given address
//       }
//       IZkLighter(zklighterProxy).depositBatch(amounts, senders, accountIndexes);

//       emit DepositClaimed(msg.sender, nonce);
//     }
//   }

//   function setGovernor(address _governor) external onlyGovernor {
//     require(_governor != address(0), "Governor cannot be zero address");
//     governor = _governor;
//   }

//   function setValidator(address validator, bool active) external onlyGovernor{
//     validators[validator] = active;
//   }

//   function withdraw(address token, address to, uint256 amount) external onlyGovernor {
//     require(amount > 0, "Invalid amount");
//     IERC20(token).safeTransfer(to, amount);
//   }
  
//   function isValidator(address validator) public view returns (bool) {
//     return validators[validator];
//   }

//   function _calculateDepositAmount(uint256 amount, uint256 feeTicker, uint256 feeAddition) internal pure returns (uint256) {
//     if (feeTicker == 0 && feeAddition == 0) {
//       return amount;
//     }
//     uint256 fee = Math.mulDiv(amount, feeTicker, FEE_DENOMINATOR, Math.Rounding.Ceil) + feeAddition;
//     require(amount >= fee, "Fee too high");
//     return amount - fee;
//   }

//   modifier onlyGovernor() {
//     require(msg.sender == governor, "Not authorized");
//     _;
//   }
// }