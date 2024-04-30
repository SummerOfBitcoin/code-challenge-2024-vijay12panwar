package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil/bech32"
	"github.com/mr-tron/base58"
	"os"
	"sort"
	"strings"
	"time"
)

type BlockHeader struct {
	Version       uint32
	PrevBlockHash string
	MerkleRoot    string
	Time          int64
	Bits          uint32
	Nonce         uint32
}

type Input struct {
	TxID         string   `json:"txid"`
	Vout         uint32   `json:"vout"`
	Prevout      Prevout  `json:"prevout"`
	Scriptsig    string   `json:"scriptsig"`
	ScriptsigAsm string   `json:"scriptsig_asm"`
	Witness      []string `json:"witness"`
	IsCoinbase   bool     `json:"is_coinbase"`
	Sequence     uint32   `json:"sequence"`
}

type Prevout struct {
	Scriptpubkey        string `json:"scriptpubkey"`
	ScriptpubkeyAsm     string `json:"scriptpubkey_asm"`
	ScriptpubkeyType    string `json:"scriptpubkey_type"`
	ScriptpubkeyAddress string `json:"scriptpubkey_address"`
	Value               uint64 `json:"value"`
}

type Transaction struct {
	Version  uint32    `json:"version"`
	Locktime uint32    `json:"locktime"`
	Vin      []Input   `json:"vin"`
	Vout     []Prevout `json:"vout"`
}

type TxInfo struct {
	TxID   string
	WTxID  string
	Fee    uint64
	Weight uint64
}

type MerkleNode struct {
	Left  *MerkleNode
	Data  []byte
	Right *MerkleNode
}

func main() {
	MineBlock()
}

var Bh = BlockHeader{
	Version:       7,
	PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
	MerkleRoot:    "",
	Time:          time.Now().Unix(),
	Bits:          0x1f00ffff,
	Nonce:         0,
}

func MineBlock() {
	netReward, TxIDs, _ := Prioritize()

	cbTx := CreateCoinbase(netReward)
	serializedcbTx, _ := SerializeTransaction(cbTx)
	fmt.Printf("CBTX: %x\n", serializedcbTx)
	TxIDs = append([]string{hex.EncodeToString(ReverseBytes(To_sha(To_sha(serializedcbTx))))}, TxIDs...)
	Bh.MerkleRoot = hex.EncodeToString(NewMerkleTree(TxIDs).Data)
	cbtxbase := CalculateBaseSize(cbTx)
	cbtxwitness := CalculateWitnessSize(cbTx)
	fmt.Println("Cbtx wt: ", cbtxwitness+(cbtxbase*4))
	if ProofOfWork(&Bh) {
		file, _ := os.Create("output.txt")
		defer file.Close()
		serializedBh := SerializeBlockHeader(&Bh)
		segserialized, _ := SegWitSerialize(cbTx)
		file.WriteString(hex.EncodeToString(serializedBh) + "\n")
		file.WriteString(hex.EncodeToString(segserialized) + "\n")
		for _, tx := range TxIDs {
			file.WriteString(tx + "\n")
		}
	}
}

const target string = "0000ffff00000000000000000000000000000000000000000000000000000000"

func CompareByteArrays(a, b []byte) int {
	if len(a) != len(b) {
		panic("Arrays must have the same length")
	}

	for i := range a {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func ProofOfWork(bh *BlockHeader) bool {
	targetBytes, _ := hex.DecodeString(target)
	for {
		serialized := SerializeBlockHeader(bh)
		hash := ReverseBytes(To_sha(To_sha(serialized)))

		if CompareByteArrays(hash, targetBytes) == -1 {
			fmt.Println("Block Mined", hex.EncodeToString(hash))
			return true
		}
		if bh.Nonce < 0x0 || bh.Nonce > 0xffffffff {
			fmt.Println("FUCKED")
			return false
		}
		bh.Nonce++
	}
}

func CreateCoinbase(netReward uint64) *Transaction {
	witnessCommitment := CreateWitnessMerkle()
	coinbaseTx := Transaction{
		Version: 1,
		Vin: []Input{
			{
				TxID: "0000000000000000000000000000000000000000000000000000000000000000",
				Vout: 0xffffffff,
				Prevout: Prevout{
					Scriptpubkey:        "0014df4bf9f3621073202be59ae590f55f42879a21a0",
					ScriptpubkeyAsm:     "0014df4bf9f3621073202be59ae590f55f42879a21a0",
					ScriptpubkeyType:    "p2pkh",
					ScriptpubkeyAddress: "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
					Value:               uint64(netReward),
				},
				IsCoinbase: true,
				Sequence:   0xffffffff,
				Scriptsig:  "03951a0604f15ccf5609013803062b9b5a0100072f425443432f20",
				Witness:    []string{"0000000000000000000000000000000000000000000000000000000000000000"},
			},
		},
		Vout: []Prevout{
			{
				Scriptpubkey:        "0014df4bf9f3621073202be59ae590f55f42879a21a0",
				ScriptpubkeyAsm:     "0014df4bf9f3621073202be59ae590f55f42879a21a0",
				ScriptpubkeyType:    "p2pkh",
				ScriptpubkeyAddress: "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
				Value:               uint64(netReward),
			},
			{
				Scriptpubkey:        "6a24" + "aa21a9ed" + witnessCommitment, //OPRETURN +OP_PUSHBYTES_36+ commitment header + witnessCommitment
				ScriptpubkeyAsm:     "OP_RETURN" + "OP_PUSHBYTES_36" + "aa21a9ed" + witnessCommitment,
				ScriptpubkeyType:    "op_return",
				ScriptpubkeyAddress: "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
				Value:               uint64(0),
			},
		},
		Locktime: 0,
	}
	return &coinbaseTx
}

func NewMerkleNode(lnode *MerkleNode, rnode *MerkleNode, data []byte) *MerkleNode {
	var mNode = MerkleNode{}
	if lnode == nil && rnode == nil {
		mNode.Data = ReverseBytes(data)
	} else {
		var prevHash = append(lnode.Data, rnode.Data...)
		mNode.Data = To_sha(To_sha(prevHash))
	}
	mNode.Left = lnode
	mNode.Right = rnode
	return &mNode
}

func NewMerkleTree(leaves []string) *MerkleNode {
	var nodes []MerkleNode

	for _, leaf := range leaves {
		data, _ := hex.DecodeString(leaf)
		var node MerkleNode = *NewMerkleNode(nil, nil, data)
		nodes = append(nodes, node)
	}

	for len(nodes) > 1 {
		var newLevel []MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			// Handle case where the total number of nodes is odd.
			if len(nodes)%2 != 0 {
				nodes = append(nodes, nodes[len(nodes)-1])
			}
			node := *NewMerkleNode(&nodes[i], &nodes[i+1], nil)
			newLevel = append(newLevel, node)
		}
		nodes = newLevel
	}
	return &nodes[0]

}

func CreateWitnessMerkle() string {
	_, _, wTxIDs := Prioritize()
	wTxIDs = append([]string{"0000000000000000000000000000000000000000000000000000000000000000"}, wTxIDs...)
	merkleRoot := NewMerkleTree(wTxIDs)
	fmt.Println("WMKR: ", hex.EncodeToString(merkleRoot.Data))
	commitment_string := hex.EncodeToString(merkleRoot.Data) + "0000000000000000000000000000000000000000000000000000000000000000"
	WitnessCommitment, _ := hex.DecodeString(commitment_string)
	WitnessCommitment = To_sha(To_sha(WitnessCommitment))
	fmt.Println("Witness Commitment: ", hex.EncodeToString(WitnessCommitment))
	return hex.EncodeToString(WitnessCommitment)
}

func Comp(a, b TxInfo) bool {
	return float64(a.Fee)/float64(a.Weight) > float64(b.Fee)/float64(b.Weight)
}
func Prioritize() (uint64, []string, []string) {
	var permittedTxIDs []string
	var permittedWTxIDs []string
	dir := "./mempool"
	files, _ := os.ReadDir(dir)
	var txInfo []TxInfo
	for _, file := range files {
		txData, err := JsonData(dir + "/" + file.Name())
		Handle(err)
		var tx Transaction
		err = json.Unmarshal([]byte(txData), &tx)
		var fee uint64 = 0
		for _, vin := range tx.Vin {
			fee += vin.Prevout.Value
		}
		for _, vout := range tx.Vout {
			fee -= vout.Value
		}
		serialized, _ := SerializeTransaction(&tx)
		segserialized, _ := SegWitSerialize(&tx)
		txID := ReverseBytes(To_sha(To_sha(serialized)))
		wtxID := ReverseBytes(To_sha(To_sha(segserialized)))
		txInfo = append(txInfo, TxInfo{TxID: hex.EncodeToString(txID), WTxID: hex.EncodeToString(wtxID), Fee: fee, Weight: uint64(CalculateWitnessSize(&tx) + CalculateBaseSize(&tx)*4)})

	}
	sort.Slice(txInfo, func(i, j int) bool {
		return Comp(txInfo[i], txInfo[j])
	})
	var PermissibleTxs []TxInfo
	var PermissibleWeight uint64 = 3889300
	var reward uint64 = 0
	for _, tx := range txInfo {
		if PermissibleWeight >= tx.Weight {
			PermissibleTxs = append(PermissibleTxs, tx)
			PermissibleWeight -= tx.Weight
			permittedTxIDs = append(permittedTxIDs, tx.TxID)
			permittedWTxIDs = append(permittedWTxIDs, tx.WTxID)
			reward += tx.Fee
		}
	}
	fmt.Println("weight: ", PermissibleWeight)
	fmt.Println("reward: ", reward)
	return reward, permittedTxIDs, permittedWTxIDs
}

func Uint16ToBytes(n uint16) []byte {
	bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(bytes, n)
	return bytes
}
func Uint32ToBytes(n uint32) []byte {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, n)
	return bytes
}

func Uint64ToBytes(n uint64) []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, n)
	return bytes
}

func ReverseBytes(data []byte) []byte {
	length := len(data)
	for i := 0; i < length/2; i++ {
		data[i], data[length-i-1] = data[length-i-1], data[i]
	}
	return data
}
func SerializeVarInt(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return append([]byte{0xfd}, Uint16ToBytes(uint16(n))...)
	case n <= 0xffffffff:
		return append([]byte{0xfe}, Uint32ToBytes(uint32(n))...)
	default:
		return append([]byte{0xff}, Uint64ToBytes(n)...)
	}
}

func SerializeTransaction(tx *Transaction) ([]byte, error) {
	var serialized []byte
	serialized = append(serialized, Uint32ToBytes(tx.Version)...)
	serialized = append(serialized, SerializeVarInt(uint64(len(tx.Vin)))...)

	for _, vin := range tx.Vin {
		txidBytes, _ := hex.DecodeString(vin.TxID)
		serialized = append(serialized, ReverseBytes(txidBytes)...)
		serialized = append(serialized, Uint32ToBytes(vin.Vout)...)
		Scriptsig_bytes, _ := hex.DecodeString(vin.Scriptsig)
		serialized = append(serialized, SerializeVarInt(uint64(len(Scriptsig_bytes)))...)
		serialized = append(serialized, Scriptsig_bytes...)
		serialized = append(serialized, Uint32ToBytes(vin.Sequence)...)
	}

	serialized = append(serialized, SerializeVarInt(uint64(len(tx.Vout)))...)

	for _, vout := range tx.Vout {
		serialized = append(serialized, Uint64ToBytes(vout.Value)...)
		scriptPubKeyBytes, err := hex.DecodeString(vout.Scriptpubkey)
		if err != nil {
			return nil, err
		}
		serialized = append(serialized, SerializeVarInt(uint64(len(scriptPubKeyBytes)))...)
		serialized = append(serialized, scriptPubKeyBytes...)
	}
	serialized = append(serialized, Uint32ToBytes(tx.Locktime)...)

	return serialized, nil
}

func SegWitSerialize(tx *Transaction) ([]byte, error) {
	var serialized []byte
	isSegwit := CheckSegWit(tx)
	serialized = append(serialized, Uint32ToBytes(tx.Version)...)
	if isSegwit {
		serialized = append(serialized, []byte{0x00, 0x01}...)
	}
	serialized = append(serialized, SerializeVarInt(uint64(len(tx.Vin)))...)

	for _, vin := range tx.Vin {
		txidBytes, _ := hex.DecodeString(vin.TxID)
		serialized = append(serialized, ReverseBytes(txidBytes)...)
		serialized = append(serialized, Uint32ToBytes(vin.Vout)...)
		Scriptsig_bytes, _ := hex.DecodeString(vin.Scriptsig)
		serialized = append(serialized, SerializeVarInt(uint64(len(Scriptsig_bytes)))...)
		serialized = append(serialized, Scriptsig_bytes...)
		serialized = append(serialized, Uint32ToBytes(vin.Sequence)...)
	}

	serialized = append(serialized, SerializeVarInt(uint64(len(tx.Vout)))...)

	for _, vout := range tx.Vout {
		serialized = append(serialized, Uint64ToBytes(vout.Value)...)
		scriptPubKeyBytes, err := hex.DecodeString(vout.Scriptpubkey)
		if err != nil {
			return nil, err
		}
		serialized = append(serialized, SerializeVarInt(uint64(len(scriptPubKeyBytes)))...)
		serialized = append(serialized, scriptPubKeyBytes...)
	}
	if isSegwit {
		for _, vin := range tx.Vin {
			serialized = append(serialized, SerializeVarInt(uint64(len(vin.Witness)))...)
			for _, witness := range vin.Witness {
				witnessBytes, _ := hex.DecodeString(witness)
				serialized = append(serialized, SerializeVarInt(uint64(len(witnessBytes)))...)
				serialized = append(serialized, witnessBytes...)
			}
		}
	}
	serialized = append(serialized, Uint32ToBytes(tx.Locktime)...)
	return serialized, nil
}

func SerializeBlockHeader(bh *BlockHeader) []byte {
	var serialized []byte
	serialized = append(serialized, Uint32ToBytes(bh.Version)...)
	prevBlockHashbytes, _ := hex.DecodeString(bh.PrevBlockHash)
	serialized = append(serialized, prevBlockHashbytes...)
	merkleRootbytes, _ := hex.DecodeString(bh.MerkleRoot)
	serialized = append(serialized, merkleRootbytes...)
	bh.Time = time.Now().Unix()
	serialized = append(serialized, Uint32ToBytes(uint32(bh.Time))...)
	serialized = append(serialized, Uint32ToBytes(bh.Bits)...)
	serialized = append(serialized, Uint32ToBytes(bh.Nonce)...)
	return serialized
}
func ExtractHexFromScriptpubkeyAsm(str []string) string {
	for i := 0; i < len(str); i++ {
		if str[i] == "OP_PUSHBYTES_20" || str[i] == "OP_PUSHBYTES_32" {
			return str[i+1]
		}
	}
	return ""
}

func Base58Encode(input []byte) []byte {
	var encoded = base58.Encode(input)
	return []byte(encoded)
}

func To_sha(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func JsonData(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func Handle(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func CheckSegWit(tx *Transaction) bool {
	for _, vin := range tx.Vin {
		if len(vin.Witness) > 0 {
			return true
		}
	}
	return false
}

func CalculateBaseSize(tx *Transaction) int {
	serialised, _ := SerializeTransaction(tx)
	return len(serialised)
}

func CalculateWitnessSize(tx *Transaction) int {
	if !CheckSegWit(tx) {
		return 0

	}
	// Inputs (witness)
	var serialized []byte
	isSegwit := CheckSegWit(tx)
	if isSegwit {
		serialized = append(serialized, []byte{0x00, 0x01}...)
	}
	if isSegwit {
		for _, vin := range tx.Vin {
			witnessCount := uint64(len(vin.Witness))
			serialized = append(serialized, SerializeVarInt(witnessCount)...)
			for _, witness := range vin.Witness {
				witnessBytes, _ := hex.DecodeString(witness)
				witnessLen := uint64(len(witnessBytes))
				serialized = append(serialized, SerializeVarInt(witnessLen)...)
				serialized = append(serialized, witnessBytes...)
			}
		}
	}
	return len(serialized)
}

var (
	ct_p2pkh  = 0
	ct_p2sh   = 0
	ct_p2wpkh = 0
	ct_p2wsh  = 0
)

func Address() {
	files, err := os.ReadDir("./mempool")
	Handle(err)
	for range files {
		var tx Transaction
		checkAddress(tx.Vin, tx.Vout)
	}
	fmt.Printf("Count of p2pkh: %d, p2sh: %d, p2wpkh: %d, p2wsh: %d\n", ct_p2pkh, ct_p2sh, ct_p2wpkh, ct_p2wsh)
}

func checkAddress(vin []Input, vout []Prevout) {
	for _, v := range vin {
		checkAddressMatch(v.Prevout.ScriptpubkeyType, v.Prevout.ScriptpubkeyAsm, v.Prevout.ScriptpubkeyAddress)
	}
	for _, v := range vout {
		checkAddressMatch(v.ScriptpubkeyType, v.ScriptpubkeyAsm, v.ScriptpubkeyAddress)
	}
}

func checkAddressMatch(scriptType, scriptAsm, scriptAddress string) {
	var address []byte
	switch scriptType {
	case "p2pkh":
		address = P2pkh(scriptAsm)
		ct_p2pkh++
	case "p2sh":
		address = P2sh(scriptAsm)
		ct_p2sh++
	case "v0_p2wpkh":
		address = P2wpkh(scriptAsm)
		ct_p2wpkh++
	case "v0_p2wsh":
		address = P2wsh(scriptAsm)
		ct_p2wsh++
	}
	if string(address) != scriptAddress {
		fmt.Printf("Address not matched - Script Type: %s, Address: %s, Scriptpubkey Address: %s\n", scriptType, address, scriptAddress)
	}
}

func P2pkh(scriptpubkey_asm string) []byte {
	pubkeyhash := ExtractHexFromScriptpubkeyAsm(strings.Split(scriptpubkey_asm, " "))
	pubkeyhash_bytes, _ := hex.DecodeString(pubkeyhash)
	version_pubkeyhash := append([]byte{0}, pubkeyhash_bytes...)
	checksum := To_sha(To_sha(version_pubkeyhash))
	return Base58Encode(append(version_pubkeyhash, checksum[:4]...))
}

func P2sh(scriptpubkey_asm string) []byte {
	hashed_script := ExtractHexFromScriptpubkeyAsm(strings.Split(scriptpubkey_asm, " "))
	hashed_script_bytes, _ := hex.DecodeString(hashed_script)
	version_hash := append([]byte{5}, hashed_script_bytes...)
	checksum := To_sha(To_sha(version_hash))
	return Base58Encode(append(version_hash, checksum[:4]...))
}

func P2wpkh(scriptpubkey_asm string) []byte {
	pubkeyHash := ExtractHexFromScriptpubkeyAsm(strings.Split(scriptpubkey_asm, " "))
	pubkeyHashBytes, _ := hex.DecodeString(pubkeyHash)
	conv, err := bech32.ConvertBits(pubkeyHashBytes, 8, 5, true)
	Handle(err)
	address, err := bech32.Encode("bc", append([]byte{0}, conv...))
	Handle(err)
	return []byte(address)
}

func P2wsh(scriptpubkey_asm string) []byte {
	witness_scriptHash := ExtractHexFromScriptpubkeyAsm(strings.Split(scriptpubkey_asm, " "))
	witness_scriptHash_bytes, _ := hex.DecodeString(witness_scriptHash)
	conv, _ := bech32.ConvertBits(witness_scriptHash_bytes, 8, 5, true)
	encodedAddress, _ := bech32.Encode("bc", append([]byte{0}, conv...))
	return []byte(encodedAddress)
}
