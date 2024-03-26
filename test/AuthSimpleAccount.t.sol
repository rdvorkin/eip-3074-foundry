pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { VmSafe } from "forge-std/Vm.sol";
import "@account-abstraction/contracts/core/EntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "src/AuthSimpleAccount.sol";
import "src/AuthSimpleAccountFactory.sol";
import "src/userOperationHelper.sol";

contract SampleContract {
    error UnexpectedSender(address expected, address actual);

    function expectSender(address expected) public payable {
        if (msg.sender != expected) revert UnexpectedSender(expected, msg.sender);
    }
}

contract AuthSimpleAccountTest is Test {
    using MessageHashUtils for bytes32;

    SampleContract public sampleContract;
    EntryPoint public entrypoint;
    VmSafe.Wallet public owner;
    VmSafe.Wallet public beneficiary;
    AuthSimpleAccount public authSimpleAccount;
    AuthSimpleAccountFactory public authSimpleAccountFactory;


    function setUp() public {
        owner = vm.createWallet("owner");
        beneficiary = vm.createWallet("beneficiary");
        entrypoint = new EntryPoint();
        authSimpleAccountFactory = new AuthSimpleAccountFactory(entrypoint);
        // authSimpleAccount = new AuthSimpleAccount(entrypoint, address(owner.addr));
        authSimpleAccount = authSimpleAccountFactory.createAccount(address(owner.addr), 0);
        sampleContract = new SampleContract();
    }

    function signUserOp(PackedUserOperation memory op, uint256 _key)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = entrypoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, hash.toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }
    
    function test_userOp() public {
        bytes32 digest = authSimpleAccount.getDigest(hex"");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
        vm.prank(address(owner.addr));
        authSimpleAccount.setAuthSignature(v, r, s);

        // Currently this is needed, if funds will be sent from 'authorized' we can remove this
        entrypoint.depositTo{value: 0.005 ether}(address(authSimpleAccount));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        bytes memory sampleContractCalldata = abi.encodeWithSelector(SampleContract.expectSender.selector, address(owner.addr));
        
        bytes memory userOpCalldata = abi.encodeWithSelector(AuthSimpleAccount.execute.selector, address(sampleContract), 0, sampleContractCalldata);
        PackedUserOperation memory userOperation = UserOperationHelper.newUserOp({
            sender: address(authSimpleAccount),
            nonce: 0,
            initCode: hex"",
            callData: userOpCalldata,
            callGasLimit: 900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });

        userOperation.signature = signUserOp(userOperation, owner.privateKey);
        ops[0] = userOperation;
        entrypoint.handleOps(ops, payable(beneficiary.addr));
    }
}