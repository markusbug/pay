// pragma solidity ^0.8.13; // TEMP: just for avoiding compiler errors

// // SPDX-License-Identifier: Apache-2.0
// pragma solidity 0.8.25;

// import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
// import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
// import "@openzeppelin/contracts/utils/Create2.sol";
// import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

// import "./interfaces/ITokenMessengerV2.sol";
// import "./EphemeralTokenBurnerV2.sol";

// // my transfer to lighter intent: https://arbiscan.io/tx/0x29f557040f045ccaed21436170dc44a448022f0b838f18926fde32e58d6b5c09
// // deployment: https://arbiscan.io/address/0x085b48ca6908dceafb4fae56c90709e1537ec9a7#code
// contract TokenBurnerSystemV2 {
//     using SafeERC20 for IERC20;
//     IERC20 private immutable usdcToken;
//     ITokenMessengerV2 private immutable tokenMessenger;

//     uint256 public standardFeeTicker;
//     uint256 public standardFeeAddition;

//     uint256 public fastFeeTicker; // = 0
//     uint256 public fastFeeAddition; // = 0

//     uint256 public standardCCTPMaxFeeNum;
//     uint256 public standardCCTPMaxFeeDenom; // max cctp fee is 0bp for standard. Governor can update it.

//     uint256 public fastCCTPMaxFeeNum; // = 1000
//     uint256 public fastCCTPMaxFeeDenom; // max cctp fee is 1bp for fast. Governor can update it. = 10_000_000
//     uint256 public fastCCTPMinFeeNum; // = 1000
//     uint256 public fastCCTPMinFeeDenom; // min cctp fee is 1bp for fast. Governor can update it. = 10_000_000

//     uint32 public fastMinFinalityThreshold; // min finality threshold for fast transfer

//     uint256 public constant LIGHTER_FEE_DENOMINATOR = 10_000_000;
//     uint32 internal constant DESTINATION_DOMAIN = 0; // Ethereum mainnet

//     address public governor;

//     mapping(address => bool) public validators;

//     constructor(
//         address _tokenMessenger, // Circle cctp token messenger contract
//         address _usdcToken, // source chain usdc contract
//         address _governor, // governor address
//         uint256 _standardFeeTicker,
//         uint256 _standardFeeAddition,
//         uint256 _fastFeeTicker,
//         uint256 _fastFeeAddition
//     ) {
//         tokenMessenger = ITokenMessengerV2(_tokenMessenger);
//         usdcToken = IERC20(_usdcToken);
//         standardFeeTicker = _standardFeeTicker;
//         standardFeeAddition = _standardFeeAddition;
//         fastFeeTicker = _fastFeeTicker;
//         fastFeeAddition = _fastFeeAddition;
//         standardCCTPMaxFeeNum = 0;
//         standardCCTPMaxFeeDenom = 10_000_000;
//         fastCCTPMaxFeeNum = 1_000;
//         fastCCTPMaxFeeDenom = 10_000_000;
//         fastCCTPMinFeeNum = 1_000;
//         fastCCTPMinFeeDenom = 10_000_000;
//         fastMinFinalityThreshold = 1_000;

//         require(
//             standardFeeTicker <= LIGHTER_FEE_DENOMINATOR,
//             "Fee ticker must be less than denominator"
//         );
//         require(
//             fastFeeTicker <= LIGHTER_FEE_DENOMINATOR,
//             "Fee ticker must be less than denominator"
//         );

//         require(_governor != address(0), "Governor cannot be zero address");
//         governor = _governor;
//     }

//     function deployAndExecuteBatch(
//         address[] calldata zklighterRecipient, // user's account address to be deposited in Zklighter
//         uint256[] calldata customAmounts, // customAmount per sender (if 0, transfer all balance) this is to avoid $1M transfer limit
//         address claimContract, // zkligher claimer contract
//         uint256 cctpMaxFee, // 1bp of the total amount
//         uint32 minFinalityThreshold // 1000 for Fast, 2000 for standard. CCTP requires this to decide fast or standard, let's keep it as a param for further changes.
//     ) external returns (address) {
//         require(zklighterRecipient.length > 0, "Empty batch");
//         require(
//             zklighterRecipient.length == customAmounts.length,
//             "Length mismatch"
//         );

//         // Only allow validators or the single recipient to call this function
//         require(
//             isValidator(msg.sender) ||
//                 (msg.sender == zklighterRecipient[0] &&
//                     zklighterRecipient.length == 1),
//             "Not permitted"
//         );

//         uint256[] memory balances = new uint256[](zklighterRecipient.length);
//         uint256 totalBalance = 0;

//         EphemeralTokenBurnerV2 burner;

//         for (uint32 i = 0; i < zklighterRecipient.length; ++i) {
//             burner = _deployTokenBurner(zklighterRecipient[i], claimContract);
//             balances[i] = usdcToken.balanceOf(address(burner));
//             if (customAmounts[i] > 0) {
//                 require(
//                     customAmounts[i] <= balances[i],
//                     "Custom amount is greater than balance"
//                 );
//                 balances[i] = customAmounts[i];
//             }
//             require(balances[i] > 0, "Nothing to transfer");
//             burner.transferToCreator(usdcToken, balances[i]);

//             totalBalance += balances[i];
//         }

//         bytes memory hookData;
//         // Make sure that minFinalityThreshold is appropriate for the fast transfer.
//         if (minFinalityThreshold <= fastMinFinalityThreshold) {
//             require(
//                 cctpMaxFee <=
//                     Math.mulDiv(
//                         totalBalance,
//                         fastCCTPMaxFeeNum,
//                         fastCCTPMaxFeeDenom,
//                         Math.Rounding.Ceil
//                     ),
//                 "CCTP max fee exceeded"
//             );
//             require(
//                 cctpMaxFee >=
//                     Math.mulDiv(
//                         totalBalance,
//                         fastCCTPMinFeeNum,
//                         fastCCTPMinFeeDenom,
//                         Math.Rounding.Ceil
//                     ),
//                 "CCTP min fee exceeded"
//             );
//             hookData = abi.encode(
//                 zklighterRecipient,
//                 balances,
//                 fastFeeTicker,
//                 fastFeeAddition
//             );
//         } else {
//             require(
//                 cctpMaxFee <=
//                     Math.mulDiv(
//                         totalBalance,
//                         standardCCTPMaxFeeNum,
//                         standardCCTPMaxFeeDenom,
//                         Math.Rounding.Ceil
//                     ),
//                 "CCTP max fee exceeded"
//             );
//             hookData = abi.encode(
//                 zklighterRecipient,
//                 balances,
//                 standardFeeTicker,
//                 standardFeeAddition
//             );
//         }

//         _receiveTransfer(
//             minFinalityThreshold,
//             hookData,
//             totalBalance,
//             cctpMaxFee,
//             claimContract
//         );

//         return address(burner);
//     }

//     function rescueTokens(
//         address zklighterRecipient, // user's account address to be deposited in Zklighter
//         IERC20 token,
//         address claimContract
//     ) external {
//         // Only allow validators or the recipient to call this function
//         require(
//             isValidator(msg.sender) || msg.sender == zklighterRecipient,
//             "Not permitted"
//         );

//         // Deploy the burner contract with CREATE2
//         EphemeralTokenBurnerV2 burner = _deployTokenBurner(
//             zklighterRecipient,
//             claimContract
//         );

//         // Execute the handoff
//         burner.rescueMoney(token);
//     }

//     function setFee(
//         uint256 _standardFeeTicker,
//         uint256 _standardFeeAddition,
//         uint256 _fastFeeTicker,
//         uint256 _fastFeeAddition
//     ) external onlyGovernor {
//         require(
//             _standardFeeTicker <= LIGHTER_FEE_DENOMINATOR,
//             "Fee ticker must be less than denominator"
//         );
//         require(
//             _fastFeeTicker <= LIGHTER_FEE_DENOMINATOR,
//             "Fee ticker must be less than denominator"
//         );
//         standardFeeTicker = _standardFeeTicker;
//         standardFeeAddition = _standardFeeAddition;
//         fastFeeTicker = _fastFeeTicker;
//         fastFeeAddition = _fastFeeAddition;
//     }

//     function setCCTPMaxFee(
//         uint256 _standardCCTPMaxFeeNum,
//         uint256 _standardCCTPMaxFeeDenom,
//         uint256 _fastCCTPMaxFeeNum,
//         uint256 _fastCCTPMaxFeeDenom,
//         uint256 _fastCCTPMinFeeNum,
//         uint256 _fastCCTPMinFeeDenom
//     ) external onlyGovernor {
//         require(
//             _standardCCTPMaxFeeDenom > 0,
//             "CCTP max fee denominator must be greater than 0"
//         );
//         require(
//             _fastCCTPMaxFeeDenom > 0,
//             "CCTP max fee denominator must be greater than 0"
//         );
//         require(
//             _standardCCTPMaxFeeNum <= _standardCCTPMaxFeeDenom,
//             "CCTP max fee numerator must be less than denominator"
//         );
//         require(
//             _fastCCTPMaxFeeNum <= _fastCCTPMaxFeeDenom,
//             "CCTP max fee numerator must be less than denominator"
//         );
//         require(
//             _fastCCTPMinFeeNum <= _fastCCTPMinFeeDenom,
//             "CCTP min fee numerator must be less than denominator"
//         );
//         standardCCTPMaxFeeNum = _standardCCTPMaxFeeNum;
//         standardCCTPMaxFeeDenom = _standardCCTPMaxFeeDenom;
//         fastCCTPMaxFeeNum = _fastCCTPMaxFeeNum;
//         fastCCTPMaxFeeDenom = _fastCCTPMaxFeeDenom;
//         fastCCTPMinFeeNum = _fastCCTPMinFeeNum;
//         fastCCTPMinFeeDenom = _fastCCTPMinFeeDenom;
//     }

//     function setMinFinalityThreshold(
//         uint32 _fastMinFinalityThreshold
//     ) external onlyGovernor {
//         fastMinFinalityThreshold = _fastMinFinalityThreshold;
//     }

//     function setGovernor(address _governor) external onlyGovernor {
//         require(_governor != address(0), "Governor cannot be zero address");
//         governor = _governor;
//     }

//     function setValidator(
//         address validator,
//         bool active
//     ) external onlyGovernor {
//         validators[validator] = active;
//     }

//     function isValidator(address validator) public view returns (bool) {
//         return validators[validator];
//     }

//     /// @notice Computes the ephemeral burner address for given parameters
//     function getTokenBurnerAddr(
//         address zklighterRecipient, // zkLighter deposit recipient
//         address claimContract // CCTP claimer contract on destination chain
//     ) public view returns (address) {
//         bytes memory creationCode = abi.encodePacked(
//             type(EphemeralTokenBurnerV2).creationCode,
//             abi.encode(zklighterRecipient, claimContract)
//         );

//         return Create2.computeAddress(0, keccak256(creationCode));
//     }

//     function _receiveTransfer(
//         uint32 minFinalityThreshold,
//         bytes memory hookData,
//         uint256 totalBalance,
//         uint256 cctpMaxFee,
//         address claimContract
//     ) internal {
//         uint256 receivedAmount = usdcToken.balanceOf(address(this));
//         require(
//             receivedAmount >= totalBalance,
//             "FCCTP: insufficient balance received"
//         );

//         bytes32 receiver = bytes32(uint256(uint160(claimContract)));
//         usdcToken.approve(address(tokenMessenger), totalBalance);

//         tokenMessenger.depositForBurnWithHook(
//             totalBalance,
//             DESTINATION_DOMAIN,
//             receiver,
//             address(usdcToken),
//             receiver,
//             cctpMaxFee,
//             minFinalityThreshold,
//             hookData
//         );
//     }

//     function _deployTokenBurner(
//         address zklighterRecipient,
//         address claimContract
//     ) internal returns (EphemeralTokenBurnerV2) {
//         address burnerAddress = getTokenBurnerAddr(
//             zklighterRecipient,
//             claimContract
//         );
//         // If the burner already exists, return it
//         if (burnerAddress.code.length > 0) {
//             return EphemeralTokenBurnerV2(burnerAddress);
//         }
//         // Deploy the burner contract
//         return
//             new EphemeralTokenBurnerV2{salt: 0}(
//                 zklighterRecipient,
//                 claimContract
//             );
//     }

//     /// @notice Check if specified address is the governor
//     modifier onlyGovernor() {
//         require(msg.sender == governor, "Not governor");
//         _;
//     }
// }
