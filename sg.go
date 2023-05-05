package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

const NUM_ROUNDS = 2000

// Network message constants
const MISSING_BLOCK = "MISSING_BLOCK"
const POST_TRANSACTION = "POST_TRANSACTION"
const PROOF_FOUND = "PROOF_FOUND"
const START_MINING = "START_MINING"

// Constants for mining
const NUM_ROUNDS_MINING = 2000

// Constants related to proof-of-work target
const POW_LEADING_ZEROES = 15

// Constants for mining rewards and default transaction fees
const COINBASE_AMT_ALLOWED = 25
const DEFAULT_TX_FEE = 1

// If a block is 6 blocks older than the current block, it is considered
// confirmed, for no better reason than that is what Bitcoin does.
// Note that the genesis block is always considered to be confirmed.
const CONFIRMED_DEPTH = 6

type FakeNet struct {
	clients map[string]interface{}
}

type Client struct {
	// net  FakeNet
	name       string
	address    string
	publicKey  *pem.Block
	privateKey *pem.Block
}

type Miner struct {
	Client
	miningRounds int
}

func NewMiner(options map[string]interface{}) *Miner {
	m := &Miner{}
	k := NewClient(map[string]interface{}{
		"name": options["name"],
	})
	m.name = k.name
	m.address = k.address
	m.publicKey = k.publicKey
	m.privateKey = k.privateKey
	m.miningRounds = NUM_ROUNDS

	return m
}

func calcAddress(key string) string {
	hash := sha256.Sum256([]byte(key))
	addr := base64.StdEncoding.EncodeToString(hash[:])
	// fmt.Printf("Generating address %s from %s\n", addr, key)
	return addr
}

func (fn *FakeNet) Register(clientList ...*Client) {
	for _, client := range clientList {
		fn.clients[client.address] = client
	}
}

func NewClient(options map[string]interface{}) *Client {
	c := &Client{}

	if options["name"] != nil {
		c.name = options["name"].(string)
	}
	// if options["publicKey"] == nil && options["privateKey"] == nil {
	reader := rand.Reader
	bitSize := 512
	var err error
	// var publicKey rsa.PublicKey
	key, err := rsa.GenerateKey(reader, bitSize)

	_ = err
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(key)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	c.privateKey = privateKeyBlock

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	c.publicKey = publicKeyBlock
	// c.address = calcAddress(c.publicKey)
	// } else {
	// 	c.publicKey = options["publicKey"]
	// 	c.privateKey = options["privateKey"]
	// }
	c.address = calcAddress(c.name) // change to public key later
	// fmt.Printf("PUB KEY BLOCK: %T\n", publicKeyBlock)
	return c
}

func main() {
	fmt.Println("Starting simulation...")
	// Client alice;
	alice := NewClient(map[string]interface{}{
		"name": "Alice",
	})
	bob := NewClient(map[string]interface{}{
		"name": "Bob",
	})
	charlie := NewClient(map[string]interface{}{
		"name": "Charlie",
	})
	fmt.Println(alice.name)
	fmt.Println(bob.name)
	fmt.Println(charlie.name)

	minnie := NewMiner(map[string]interface{}{
		"name": "Minnie",
	})
	mickey := NewMiner(map[string]interface{}{
		"name": "Mickey",
	})

	fmt.Println(minnie.name)
	fmt.Println(mickey.name)

}
