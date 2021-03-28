import { ethers, Wallet, UnsignedTransaction, utils, BigNumber } from "ethers";
import { arrayify, DataOptions, hexlify, isBytesLike, SignatureLike, splitSignature, stripZeros, } from "@ethersproject/bytes";
import { task, types } from "hardhat/config";
import { contractFactory } from "../contracts";
import * as RLP from "@ethersproject/rlp";

import { Logger } from "@ethersproject/logger";
import { getSingletonAddress } from "../information";
import { buildSafeTransaction, populateExecuteTx, safeApproveHash } from "../../../utils/execution";
const logger = new Logger("0.1.0");

const transactionFields = [
    { name: "nonce", maxLength: 32, numeric: true },
    { name: "gasPrice", maxLength: 32, numeric: true },
    { name: "gasLimit", maxLength: 32, numeric: true },
    { name: "to", length: 20 },
    { name: "value", maxLength: 32, numeric: true },
    { name: "data" },
];

interface AccessListEntry {
    address: string,
    slots?: string[]
}

type AccessList = AccessListEntry[]

export function serialize(transaction: UnsignedTransaction, accessList: AccessList, signature?: SignatureLike): string {
    const raw: Array<Array<any> | string | Uint8Array> = [];

    let chainId = 0;
    if (transaction.chainId != null) {
        // A chainId was provided; if non-zero we'll use EIP-155
        chainId = transaction.chainId;

        if (typeof (chainId) !== "number") {
            logger.throwArgumentError("invalid transaction.chainId", "transaction", transaction);
        }

    } else if (signature && !isBytesLike(signature) && signature.v && signature.v > 28) {
        // No chainId provided, but the signature is signing with EIP-155; derive chainId
        chainId = Math.floor((signature.v - 35) / 2);
    }
    raw.push(stripZeros(arrayify(chainId)));

    transactionFields.forEach(function (fieldInfo) {
        let value = (<any>transaction)[fieldInfo.name] || ([]);
        const options: DataOptions = {};
        if (fieldInfo.numeric) { options.hexPad = "left"; }
        value = arrayify(hexlify(value, options));

        // Fixed-width field
        if (fieldInfo.length && value.length !== fieldInfo.length && value.length > 0) {
            logger.throwArgumentError("invalid length for " + fieldInfo.name, ("transaction:" + fieldInfo.name), value);
        }

        // Variable-width (with a maximum)
        if (fieldInfo.maxLength) {
            value = stripZeros(value);
            if (value.length > fieldInfo.maxLength) {
                logger.throwArgumentError("invalid length for " + fieldInfo.name, ("transaction:" + fieldInfo.name), value);
            }
        }

        raw.push(hexlify(value));
    });
    raw.push(accessList.map(entry => [entry.address, entry.slots || []]));

    // Requesting an unsigned transation
    if (!signature) {
        return "0x01" + RLP.encode(raw).slice(2);
    }

    // The splitSignature will ensure the transaction has a recoveryParam in the
    // case that the signTransaction function only adds a v.
    const sig = splitSignature(signature);

    raw.push(stripZeros(arrayify(sig.recoveryParam)));
    raw.push(stripZeros(arrayify(sig.r)));
    raw.push(stripZeros(arrayify(sig.s)));

    return "0x01" + RLP.encode(raw).slice(2);
}

const Forwarder = new ethers.utils.Interface(['function forward(address payable target) payable public'])

task("execute", "Executes a Safe transaction")
    .addParam("address", "Address or ENS name of the Safe to check", undefined, types.string)
    .addParam("to", "Address of the target", undefined, types.string)
    .addParam("value", "Value in ETH", "0", types.string, true)
    .addParam("data", "Data as hex string", "0x", types.string, true)
    .addParam("signatures", "Comma seperated list of signatures", undefined, types.string, true)
    .addFlag("delegatecall", "Indicator if tx should be executed as a delegatecall")
    .setAction(async (taskArgs, hre) => {
        const mnemonic = process.env.MNEMONIC
        if (!mnemonic) throw Error("No mnemonic provided")
        const relayer = Wallet.fromMnemonic(mnemonic)
        const safe = (await contractFactory(hre, "GnosisSafe")).attach(taskArgs.address)
        const safeAddress = await safe.resolvedAddress
        console.log(`Using Safe at ${safeAddress} with ${relayer.address}`)
        const threshold = await safe.getThreshold()
        const nonce = await safe.nonce()
        console.log({ threshold, nonce })
        const tx = buildSafeTransaction({ to: taskArgs.to, nonce })
        const populatedTx: any = await populateExecuteTx(safe, tx, [ await safeApproveHash(relayer, safe, tx, true) ])
        const relayerNonce = await hre.ethers.provider.getTransactionCount(relayer.address)
        populatedTx.chainId = hre.ethers.provider.network.chainId
        populatedTx.gasLimit = BigNumber.from("1000000")
        populatedTx.gasPrice = BigNumber.from("10000000000")
        populatedTx.nonce = relayerNonce
        console.log({ populatedTx })
        const accessList: AccessList = [
            { address: await getSingletonAddress(hre, safe.address) }, // Singleton address
        ]
        const setializedTx = serialize(populatedTx, accessList)
        const signature = relayer._signingKey().signDigest(utils.keccak256(setializedTx))
        console.log({signature})
        const signedTx = serialize(populatedTx, accessList, signature)

        populatedTx.hash = utils.keccak256(signedTx)
        const hash = await hre.ethers.provider.perform("sendTransaction", { signedTransaction: signedTx });
        console.log({hash})
        await hre.ethers.provider._wrapTransaction(populatedTx, hash);
    });