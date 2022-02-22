package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"log"
)

func payToWitnessPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(pubKeyHash).Script()
}

func payToWitnessScriptHashScript(scriptHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(scriptHash).Script()
}

type Alice struct {
	outpoint      *wire.OutPoint
	wif           *btcutil.WIF
	addr          *btcutil.AddressWitnessPubKeyHash
	p2AliceScript []byte
	secret        []byte
	commit        []byte
	script0       []byte
	script1       []byte
	script2       []byte
}

type Bob struct {
	outpoint    *wire.OutPoint
	wif         *btcutil.WIF
	addr        *btcutil.AddressWitnessPubKeyHash
	p2BobScript []byte
	secret      []byte
	commit      []byte
	script0     []byte
	script1     []byte
	script2     []byte
}

func (alice *Alice) Stage0() (*wire.OutPoint, *btcutil.AddressWitnessPubKeyHash, []byte) {
	hash, err := chainhash.NewHashFromStr("8ae4057356d226ff38fc8321c50d8b2ad3cc84a60677f7a50ae34f3fff10b92e")
	if err != nil {
		log.Fatalln(err)
	}
	alice.outpoint = wire.NewOutPoint(hash, 1)

	alice.wif, err = btcutil.DecodeWIF("cSABfujfZR3NsV6WpKkfQJWSr9P3LPtzZphnMRXaiumEngRx4unD")
	if err != nil {
		log.Fatalln(err)
	}

	alice.addr, err = btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(alice.wif.SerializePubKey()), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	alice.p2AliceScript, err = payToWitnessPubKeyHashScript(alice.addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	alice.secret = []byte("MakeBitcoinCurrencyAgain")

	alice.commit = btcutil.Hash160(alice.secret)

	return alice.outpoint, alice.addr, alice.commit
}

func (bob *Bob) Stage0() (*wire.OutPoint, *btcutil.AddressWitnessPubKeyHash, []byte) {
	hash, err := chainhash.NewHashFromStr("2884bbb3f627504e4d8b7bb3cea7ea3ec1af9f94c2b12670dc56cf5f0f385c74")
	if err != nil {
		log.Fatalln(err)
	}
	bob.outpoint = wire.NewOutPoint(hash, 1)

	bob.wif, err = btcutil.DecodeWIF("cTuhaqvfkCe4gTw3ARH9CdTAHUVZucTHi5d7sdwiP1hRH3uZXshV")
	if err != nil {
		log.Fatalln(err)
	}

	bob.addr, err = btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(bob.wif.SerializePubKey()), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	bob.p2BobScript, err = payToWitnessPubKeyHashScript(bob.addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	bob.secret = []byte("NeverSayDigitalGold")

	bob.commit = btcutil.Hash160(bob.secret)

	return bob.outpoint, bob.addr, bob.commit
}

func (alice *Alice) Stage1(bobOutpoint *wire.OutPoint, bobAddr *btcutil.AddressWitnessPubKeyHash, bobCommit []byte) wire.TxWitness {
	var err error

	builder0 := txscript.NewScriptBuilder()
	builder0.AddOp(txscript.OP_IF)
	builder0.AddOp(txscript.OP_HASH160).AddData(alice.commit).AddOp(txscript.OP_EQUALVERIFY)
	builder0.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(alice.addr.WitnessProgram())
	builder0.AddOp(txscript.OP_ELSE)
	builder0.AddInt64(144).AddOp(txscript.OP_CHECKSEQUENCEVERIFY).AddOp(txscript.OP_DROP)
	builder0.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bobAddr.WitnessProgram())
	builder0.AddOp(txscript.OP_ENDIF)
	builder0.AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)

	alice.script0, err = builder0.Script()
	if err != nil {
		log.Fatalln(err)
	}

	script0Hash := sha256.Sum256(alice.script0)
	contract0Addr, err := btcutil.NewAddressWitnessScriptHash(script0Hash[:], &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	p2Contract0Script, err := payToWitnessScriptHashScript(contract0Addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	builder1 := txscript.NewScriptBuilder()
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bobCommit).AddOp(txscript.OP_EQUALVERIFY)
	builder1.AddOp(txscript.OP_SIZE).AddOp(txscript.OP_NIP).AddInt64(20).AddOp(txscript.OP_LESSTHANOREQUAL)
	builder1.AddOp(txscript.OP_SWAP)
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(alice.commit).AddOp(txscript.OP_EQUALVERIFY)
	builder1.AddOp(txscript.OP_SIZE).AddOp(txscript.OP_NIP).AddInt64(20).AddOp(txscript.OP_LESSTHANOREQUAL)
	builder1.AddOp(txscript.OP_EQUAL)
	builder1.AddOp(txscript.OP_IF)
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(alice.addr.WitnessProgram())
	builder1.AddOp(txscript.OP_ELSE)
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bobAddr.WitnessProgram())
	builder1.AddOp(txscript.OP_ENDIF)
	builder1.AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)

	alice.script1, err = builder1.Script()
	if err != nil {
		log.Fatalln(err)
	}

	script1Hash := sha256.Sum256(alice.script1)
	contract1Addr, err := btcutil.NewAddressWitnessScriptHash(script1Hash[:], &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	p2Contract1Script, err := payToWitnessScriptHashScript(contract1Addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	builder2 := txscript.NewScriptBuilder()
	builder2.AddOp(txscript.OP_IF)
	builder2.AddOp(txscript.OP_HASH160).AddData(bobCommit).AddOp(txscript.OP_EQUALVERIFY)
	builder2.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bobAddr.WitnessProgram())
	builder2.AddOp(txscript.OP_ELSE)
	builder2.AddInt64(144).AddOp(txscript.OP_CHECKSEQUENCEVERIFY).AddOp(txscript.OP_DROP)
	builder2.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(alice.addr.WitnessProgram())
	builder2.AddOp(txscript.OP_ENDIF)
	builder2.AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)

	alice.script2, err = builder2.Script()
	if err != nil {
		log.Fatalln(err)
	}

	script2Hash := sha256.Sum256(alice.script2)
	contract2Addr, err := btcutil.NewAddressWitnessScriptHash(script2Hash[:], &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	p2Contract2Script, err := payToWitnessScriptHashScript(contract2Addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(alice.outpoint, nil, nil))
	tx.AddTxIn(wire.NewTxIn(bobOutpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(6500, p2Contract0Script))
	tx.AddTxOut(wire.NewTxOut(6500, p2Contract1Script))
	tx.AddTxOut(wire.NewTxOut(6500, p2Contract2Script))

	txSigHashes := txscript.NewTxSigHashes(tx)

	alicePrivKey := btcec.PrivateKey(*alice.wif.PrivKey.ToECDSA())

	aliceTxWitness, err := txscript.WitnessSignature(tx, txSigHashes, 0, 10000, alice.p2AliceScript, txscript.SigHashAll, &alicePrivKey, alice.wif.CompressPubKey)
	if err != nil {
		log.Fatalln(err)
	}

	return aliceTxWitness
}

func (bob *Bob) Stage1(aliceOutpoint *wire.OutPoint, aliceAddr *btcutil.AddressWitnessPubKeyHash, aliceCommit []byte, aliceTxWitness wire.TxWitness) *wire.MsgTx {
	var err error

	builder0 := txscript.NewScriptBuilder()
	builder0.AddOp(txscript.OP_IF)
	builder0.AddOp(txscript.OP_HASH160).AddData(aliceCommit).AddOp(txscript.OP_EQUALVERIFY)
	builder0.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(aliceAddr.WitnessProgram())
	builder0.AddOp(txscript.OP_ELSE)
	builder0.AddInt64(144).AddOp(txscript.OP_CHECKSEQUENCEVERIFY).AddOp(txscript.OP_DROP)
	builder0.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bob.addr.WitnessProgram())
	builder0.AddOp(txscript.OP_ENDIF)
	builder0.AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)

	bob.script0, err = builder0.Script()
	if err != nil {
		log.Fatalln(err)
	}

	script0Hash := sha256.Sum256(bob.script0)
	contract0Addr, err := btcutil.NewAddressWitnessScriptHash(script0Hash[:], &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	p2Contract0Script, err := payToWitnessScriptHashScript(contract0Addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	builder1 := txscript.NewScriptBuilder()
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bob.commit).AddOp(txscript.OP_EQUALVERIFY)
	builder1.AddOp(txscript.OP_SIZE).AddOp(txscript.OP_NIP).AddInt64(20).AddOp(txscript.OP_LESSTHANOREQUAL)
	builder1.AddOp(txscript.OP_SWAP)
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(aliceCommit).AddOp(txscript.OP_EQUALVERIFY)
	builder1.AddOp(txscript.OP_SIZE).AddOp(txscript.OP_NIP).AddInt64(20).AddOp(txscript.OP_LESSTHANOREQUAL)
	builder1.AddOp(txscript.OP_EQUAL)
	builder1.AddOp(txscript.OP_IF)
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(aliceAddr.WitnessProgram())
	builder1.AddOp(txscript.OP_ELSE)
	builder1.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bob.addr.WitnessProgram())
	builder1.AddOp(txscript.OP_ENDIF)
	builder1.AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)

	bob.script1, err = builder1.Script()
	if err != nil {
		log.Fatalln(err)
	}

	script1Hash := sha256.Sum256(bob.script1)
	contract1Addr, err := btcutil.NewAddressWitnessScriptHash(script1Hash[:], &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	p2Contract1Script, err := payToWitnessScriptHashScript(contract1Addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	builder2 := txscript.NewScriptBuilder()
	builder2.AddOp(txscript.OP_IF)
	builder2.AddOp(txscript.OP_HASH160).AddData(bob.commit).AddOp(txscript.OP_EQUALVERIFY)
	builder2.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(bob.addr.WitnessProgram())
	builder2.AddOp(txscript.OP_ELSE)
	builder2.AddInt64(144).AddOp(txscript.OP_CHECKSEQUENCEVERIFY).AddOp(txscript.OP_DROP)
	builder2.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(aliceAddr.WitnessProgram())
	builder2.AddOp(txscript.OP_ENDIF)
	builder2.AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)

	bob.script2, err = builder2.Script()
	if err != nil {
		log.Fatalln(err)
	}

	script2Hash := sha256.Sum256(bob.script2)
	contract2Addr, err := btcutil.NewAddressWitnessScriptHash(script2Hash[:], &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	p2Contract2Script, err := payToWitnessScriptHashScript(contract2Addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	bobPrivKey := btcec.PrivateKey(*bob.wif.PrivKey.ToECDSA())

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(aliceOutpoint, nil, aliceTxWitness))
	tx.AddTxIn(wire.NewTxIn(bob.outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(6500, p2Contract0Script))
	tx.AddTxOut(wire.NewTxOut(6500, p2Contract1Script))
	tx.AddTxOut(wire.NewTxOut(6500, p2Contract2Script))

	txSigHashes := txscript.NewTxSigHashes(tx)

	bobTxWitness, err := txscript.WitnessSignature(tx, txSigHashes, 1, 10000, bob.p2BobScript, txscript.SigHashAll, &bobPrivKey, bob.wif.CompressPubKey)
	if err != nil {
		log.Fatalln(err)
	}

	tx.TxIn[1].Witness = bobTxWitness
	return tx
}

func (alice *Alice) Stage2() []byte {
	return alice.secret
}

func (bob *Bob) Stage2() []byte {
	return bob.secret
}

func (alice *Alice) Stage3(prevTx *wire.MsgTx, bobSecret []byte) *wire.MsgTx {
	prevTxHash := prevTx.TxHash()
	alicePrivKey := btcec.PrivateKey(*alice.wif.PrivKey.ToECDSA())

	tx := wire.NewMsgTx(2)

	if (len(alice.secret) <= 20) == (len(bobSecret) <= 20) {
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 0), nil, nil))
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 1), nil, nil))
		tx.AddTxOut(wire.NewTxOut(12700, alice.p2AliceScript))

		txSigHashes := txscript.NewTxSigHashes(tx)

		aliceTxWitness0, err := txscript.WitnessSignature(tx, txSigHashes, 0, 6500, alice.script0, txscript.SigHashAll, &alicePrivKey, alice.wif.CompressPubKey)
		if err != nil {
			log.Fatalln(err)
		}

		tx.TxIn[0].Witness = append(aliceTxWitness0, alice.secret, []byte{1}, alice.script0)

		aliceTxWitness1, err := txscript.WitnessSignature(tx, txSigHashes, 1, 6500, alice.script1, txscript.SigHashAll, &alicePrivKey, alice.wif.CompressPubKey)
		if err != nil {
			log.Fatalln(err)
		}

		tx.TxIn[1].Witness = append(aliceTxWitness1, alice.secret, bobSecret, alice.script1)
	} else {
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 0), nil, nil))
		tx.AddTxOut(wire.NewTxOut(6200, alice.p2AliceScript))

		txSigHashes := txscript.NewTxSigHashes(tx)

		aliceTxWitness0, err := txscript.WitnessSignature(tx, txSigHashes, 0, 6500, alice.script0, txscript.SigHashAll, &alicePrivKey, alice.wif.CompressPubKey)
		if err != nil {
			log.Fatalln(err)
		}

		tx.TxIn[0].Witness = append(aliceTxWitness0, alice.secret, []byte{1}, alice.script0)
	}

	return tx
}

func (bob *Bob) Stage3(prevTx *wire.MsgTx, aliceSecret []byte) *wire.MsgTx {
	prevTxHash := prevTx.TxHash()
	bobPrivKey := btcec.PrivateKey(*bob.wif.PrivKey.ToECDSA())

	tx := wire.NewMsgTx(2)

	if (len(aliceSecret) <= 20) != (len(bob.secret) <= 20) {
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 2), nil, nil))
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 1), nil, nil))
		tx.AddTxOut(wire.NewTxOut(12700, bob.p2BobScript))

		txSigHashes := txscript.NewTxSigHashes(tx)

		bobTxWitness0, err := txscript.WitnessSignature(tx, txSigHashes, 0, 6500, bob.script2, txscript.SigHashAll, &bobPrivKey, bob.wif.CompressPubKey)
		if err != nil {
			log.Fatalln(err)
		}

		tx.TxIn[0].Witness = append(bobTxWitness0, bob.secret, []byte{1}, bob.script2)

		bobTxWitness1, err := txscript.WitnessSignature(tx, txSigHashes, 1, 6500, bob.script1, txscript.SigHashAll, &bobPrivKey, bob.wif.CompressPubKey)
		if err != nil {
			log.Fatalln(err)
		}

		tx.TxIn[1].Witness = append(bobTxWitness1, aliceSecret, bob.secret, bob.script1)
	} else {
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 2), nil, nil))
		tx.AddTxOut(wire.NewTxOut(6200, bob.p2BobScript))

		txSigHashes := txscript.NewTxSigHashes(tx)

		bobTxWitness0, err := txscript.WitnessSignature(tx, txSigHashes, 0, 6500, bob.script2, txscript.SigHashAll, &bobPrivKey, bob.wif.CompressPubKey)
		if err != nil {
			log.Fatalln(err)
		}

		tx.TxIn[0].Witness = append(bobTxWitness0, bob.secret, []byte{1}, bob.script2)
	}

	return tx
}

func Round0() {
	alice := new(Alice)
	bob := new(Bob)

	aliceOutpoint, aliceAddr, aliceCommit := alice.Stage0()
	bobOutpoint, bobAddr, bobCommit := bob.Stage0()

	aliceTxWitness := alice.Stage1(bobOutpoint, bobAddr, bobCommit)
	tx0 := bob.Stage1(aliceOutpoint, aliceAddr, aliceCommit, aliceTxWitness)

	buf := new(bytes.Buffer)
	if err := tx0.Serialize(buf); err != nil {
		log.Fatalln(err)
	}
	log.Println(hex.EncodeToString(buf.Bytes()))

	aliceSecret := alice.Stage2()
	bobSecret := bob.Stage2()

	tx1Alice := alice.Stage3(tx0, bobSecret)
	tx1Bob := bob.Stage3(tx0, aliceSecret)

	buf = new(bytes.Buffer)
	if err := tx1Alice.Serialize(buf); err != nil {
		log.Fatalln(err)
	}
	log.Println(hex.EncodeToString(buf.Bytes()))
	buf = new(bytes.Buffer)
	if err := tx1Bob.Serialize(buf); err != nil {
		log.Fatalln(err)
	}
	log.Println(hex.EncodeToString(buf.Bytes()))
}

func (alice *Alice) Round1Stage0() (*wire.OutPoint, *btcutil.AddressWitnessPubKeyHash, []byte) {
	hash, err := chainhash.NewHashFromStr("49a2c9314017fc838c8174b68b747a630659f987504dbf7df625d2fc882299a9")
	if err != nil {
		log.Fatalln(err)
	}
	alice.outpoint = wire.NewOutPoint(hash, 1)

	alice.wif, err = btcutil.DecodeWIF("cSABfujfZR3NsV6WpKkfQJWSr9P3LPtzZphnMRXaiumEngRx4unD")
	if err != nil {
		log.Fatalln(err)
	}

	alice.addr, err = btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(alice.wif.SerializePubKey()), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	alice.p2AliceScript, err = payToWitnessPubKeyHashScript(alice.addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	alice.secret = []byte("MakeBitcoinCurrencyAgain")

	alice.commit = btcutil.Hash160(nil)

	return alice.outpoint, alice.addr, alice.commit
}

func (bob *Bob) Round1Stage0() (*wire.OutPoint, *btcutil.AddressWitnessPubKeyHash, []byte) {
	hash, err := chainhash.NewHashFromStr("62dd6e644cae1da51da540b91b5d3e777c52493f6ec4f0ee3116b9cc31f682c3")
	if err != nil {
		log.Fatalln(err)
	}
	bob.outpoint = wire.NewOutPoint(hash, 0)

	bob.wif, err = btcutil.DecodeWIF("cTuhaqvfkCe4gTw3ARH9CdTAHUVZucTHi5d7sdwiP1hRH3uZXshV")
	if err != nil {
		log.Fatalln(err)
	}

	bob.addr, err = btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(bob.wif.SerializePubKey()), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalln(err)
	}

	bob.p2BobScript, err = payToWitnessPubKeyHashScript(bob.addr.WitnessProgram())
	if err != nil {
		log.Fatalln(err)
	}

	bob.secret = []byte("NeverSayDigitalGold")

	bob.commit = btcutil.Hash160(bob.secret)

	return bob.outpoint, bob.addr, bob.commit
}

func (bob *Bob) Round1Stage3(prevTx *wire.MsgTx) *wire.MsgTx {
	prevTxHash := prevTx.TxHash()
	bobPrivKey := btcec.PrivateKey(*bob.wif.PrivKey.ToECDSA())

	tx := wire.NewMsgTx(2)

	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 2), nil, nil))
	tx.AddTxOut(wire.NewTxOut(6200, bob.p2BobScript))

	txSigHashes := txscript.NewTxSigHashes(tx)

	bobTxWitness0, err := txscript.WitnessSignature(tx, txSigHashes, 0, 6500, bob.script2, txscript.SigHashAll, &bobPrivKey, bob.wif.CompressPubKey)
	if err != nil {
		log.Fatalln(err)
	}

	tx.TxIn[0].Witness = append(bobTxWitness0, bob.secret, []byte{1}, bob.script2)

	return tx
}

func (bob *Bob) Round1Stage4(prevTx *wire.MsgTx) *wire.MsgTx {
	prevTxHash := prevTx.TxHash()
	bobPrivKey := btcec.PrivateKey(*bob.wif.PrivKey.ToECDSA())

	tx := wire.NewMsgTx(2)

	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxHash, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(6200, bob.p2BobScript))

	txSigHashes := txscript.NewTxSigHashes(tx)

	bobTxWitness0, err := txscript.WitnessSignature(tx, txSigHashes, 0, 6500, bob.script0, txscript.SigHashAll, &bobPrivKey, bob.wif.CompressPubKey)
	if err != nil {
		log.Fatalln(err)
	}

	tx.TxIn[0].Sequence = 144
	tx.TxIn[0].Witness = append(bobTxWitness0, []byte{0}, bob.script0)

	return tx
}

func Round1() {
	alice := new(Alice)
	bob := new(Bob)

	aliceOutpoint, aliceAddr, aliceCommit := alice.Round1Stage0()
	bobOutpoint, bobAddr, bobCommit := bob.Round1Stage0()

	aliceTxWitness := alice.Stage1(bobOutpoint, bobAddr, bobCommit)
	tx0 := bob.Stage1(aliceOutpoint, aliceAddr, aliceCommit, aliceTxWitness)

	buf := new(bytes.Buffer)
	if err := tx0.Serialize(buf); err != nil {
		log.Fatalln(err)
	}
	log.Println(hex.EncodeToString(buf.Bytes()))

	tx1Bob := bob.Round1Stage3(tx0)

	buf = new(bytes.Buffer)
	if err := tx1Bob.Serialize(buf); err != nil {
		log.Fatalln(err)
	}
	log.Println(hex.EncodeToString(buf.Bytes()))

	tx2Bob := bob.Round1Stage4(tx0)

	buf = new(bytes.Buffer)
	if err := tx2Bob.Serialize(buf); err != nil {
		log.Fatalln(err)
	}
	log.Println(hex.EncodeToString(buf.Bytes()))
}

func main() {
	Round0()
	Round1()
}
