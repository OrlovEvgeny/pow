package main

import (
	"bufio"
	"bytes"
	"container/ring"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"pow/hashcash"
	"strings"
	"time"
)

type opcode int

const (
	REQUEST_CHALLENGE opcode = iota
	CHALLENGE
	SOLVED_CHALLENGE
	ACCESS_GRANTED
	REJECT
	MSG
)

var opcodesName = [...]string{"REQUEST_CHALLENGE", "CHALLENGE", "SOLVED_CHALLENGE", "ACCESS_GRANTED", "REJECT", "MSG"}

func (o opcode) String() string {
	return opcodesName[o]
}

const (
	serverUsage = `usage: %s pow tcp-server
Run TCP server

Options:
`
	clientUsage = `usage: %s pow client

Options:
`
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s client|server\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(os.Args) < 2 {
		log.Fatalf("error: wrong number of arguments")
	}

	quotesRing = ring.New(len(quotes))
	for i := 0; i < quotesRing.Len(); i++ {
		quotesRing.Value = quotes[i]
		quotesRing = quotesRing.Next()
	}

	var err error
	switch os.Args[1] {
	case "client":
		err = client()
	case "server":
		err = server()
	default:
		err = fmt.Errorf("error: unknown command - %s", os.Args[1])
	}

	if err != nil {
		log.Fatalf("error: %s", err)
	}
}

var (
	serverFlags    = flag.NewFlagSet("server", flag.ContinueOnError)
	flagAddr       = serverFlags.String("addr", "127.0.0.1:9001", "server to listen on")
	flagAlgo       = serverFlags.String("algo", hashcash.SHA256.String(), "algorithm. One of SHA-1, SHA-256, SHA-512")
	flagDifficulty = serverFlags.Int("d", 5, "pow algorithm difficulty level")
	flagTTL        = serverFlags.Duration("ttl", 10*time.Second, "ttl for pow")
	privateKey     string
)

func server() error {
	serverFlags.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), serverUsage, os.Args[0])
		serverFlags.PrintDefaults()
	}

	if err := serverFlags.Parse(os.Args[2:]); err != nil {
		return err
	}

	pkEnv, ok := os.LookupEnv("PRIVATE_KEY")
	if !ok {
		return errors.New("env PRIVATE_KEY is not defined")
	}
	privateKey = pkEnv

	listener, err := net.Listen("tcp", *flagAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("[%s] accepted new connection\n", conn.RemoteAddr())
		go func(conn net.Conn) {
			defer conn.Close()

			if err := challengeHandler(conn); err != nil {
				if errors.Is(err, io.EOF) {
					log.Printf("[%s] connection close\n", conn.RemoteAddr())
					return
				}
				log.Printf("chanllenge: %s", err)
				return
			}

			tick := time.NewTicker(3 * time.Second)
			defer tick.Stop()
			for {
				<-tick.C
				if err := write(conn, MSG, []byte(nextQuote())); err != nil {
					if errors.Is(err, io.EOF) {
						log.Printf("[%s] connection close\n", conn.RemoteAddr())
						return
					}
					log.Printf("connection write: %s\n", err)
				}
			}
		}(conn)
	}
}

var (
	clientFlags     = flag.NewFlagSet("client", flag.ContinueOnError)
	srvDstFlag      = clientFlags.String("dst", "127.0.0.1:9001", "server dst addr")
	maxAttemptsFlag = clientFlags.Int("max-attemts", 1000, "max attempts")
)

func client() error {
	clientFlags.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), clientUsage, os.Args[0])
		clientFlags.PrintDefaults()
	}

	if err := clientFlags.Parse(os.Args[2:]); err != nil {
		return err
	}

	conn, err := net.Dial("tcp", *srvDstFlag)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("connection open. %s\n", REQUEST_CHALLENGE)
	if err = write(conn, REQUEST_CHALLENGE, []byte{}); err != nil {
		return fmt.Errorf("connection write: %w", err)
	}
	for {
		msg, err := read(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return err
			}
			return fmt.Errorf("connection read: %w", err)
		}
		opcodeCmd := bytes.ToUpper(bytes.TrimSpace(bytes.Split(msg, []byte(" "))[0]))
		switch string(opcodeCmd) {
		case CHALLENGE.String():
			stamp := deserializeMessage(CHALLENGE, msg)
			log.Printf("[%s]: %s\n", CHALLENGE, stamp)
			solve, err := hashcash.Compute(*maxAttemptsFlag, stamp)
			if err != nil {
				log.Printf("challenge compute error: %s", err)
			}
			log.Printf("[%s]: %s\n", SOLVED_CHALLENGE, solve)
			if err = write(conn, SOLVED_CHALLENGE, []byte(solve)); err != nil {
				return fmt.Errorf("connection write: %w", err)
			}
		case ACCESS_GRANTED.String():
			log.Printf("[%s]: %s\n ", ACCESS_GRANTED, deserializeMessage(ACCESS_GRANTED, msg))
		case REJECT.String():
			return fmt.Errorf("[%s]: %s\n", REJECT, deserializeMessage(REJECT, msg))
		case MSG.String():
			log.Printf("[%s]: %s\n", MSG, deserializeMessage(MSG, msg))
		default:
			return fmt.Errorf("[%s]: %s", REJECT, deserializeMessage(REJECT, msg))
		}
	}
}

func challengeHandler(conn net.Conn) error {
	hc := hashcash.New(hashcash.LookupByName(*flagAlgo), hashcash.WithPrivateKey(privateKey), hashcash.WithBits(*flagDifficulty))
	for {
		msg, err := read(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return err
			}
			return fmt.Errorf("connection read: %w", err)
		}
		opcodeCmd := bytes.ToUpper(bytes.TrimSpace(bytes.Split(msg, []byte(" "))[0]))
		switch string(opcodeCmd) {
		case REQUEST_CHALLENGE.String():
			stamp := hc.MintStamp("/ACCESS_TO_WOLF_PACK/", time.Now().Add(*flagTTL))
			if err = write(conn, CHALLENGE, []byte(stamp)); err != nil {
				return fmt.Errorf("connection write: %w", err)
			}
		case SOLVED_CHALLENGE.String():
			stamp := strings.TrimSpace(strings.TrimPrefix(string(msg), SOLVED_CHALLENGE.String()))
			if err = hashcash.Verify(privateKey, stamp); err != nil {
				if err = write(conn, REJECT, []byte(err.Error())); err != nil {
					return fmt.Errorf("connection write: %w", err)
				}
				return fmt.Errorf("connection %s: %w", REJECT, err)
			}
			if err = write(conn, ACCESS_GRANTED, []byte("Welcome to Wolf Pack. AUUFFFF!")); err != nil {
				return fmt.Errorf("connection write: %w", err)
			}
			return nil
		default:
			if err = write(conn, REJECT, []byte("unknown command")); err != nil {
				return fmt.Errorf("connection write: %w", err)
			}
		}
	}
}

func read(conn net.Conn) ([]byte, error) {
	for {
		msg, err := bufio.NewReader(conn).ReadBytes('\n')
		if err != nil {
			return []byte{}, err
		}
		return msg, err
	}
}

func write(conn net.Conn, opcodeCmd opcode, msg []byte) error {
	data := append([]byte(opcodeCmd.String()), " "...)
	data = append(data, msg...)
	data = append(data, '\n')
	_, err := conn.Write(data)
	return err
}

func deserializeMessage(opcodeCmd opcode, msg []byte) string {
	return strings.TrimSpace(strings.TrimPrefix(string(msg), opcodeCmd.String()))
}

var (
	quotes = [...]string{
		"Я знал настоящего волка — он был просрочен и кефир не пил.",
		"Хочешь, будь волком. Это твоё дело. Главное надень овечью шкуру.",
		"В этой жизни ты либо волк, либо не волк.",
		"Если волк молчит, то лучше его не перебивай.",
		"Внутри нас живёт волк. Но если мы будем вести себя подло, не сомневайтесь, он вскоре умрёт.",
		"Запомните волчья ягода не из волков.",
		"Работа не волк, работа это ворк, а волк — это ходить.",
		"Волк слабее льва и тигра, но в цирке не выступает.",
		"Под маской одинокого волка зачастую скрывается трусливый баран.",
		"Я словно волк — всегда осторожный и в меру голодный.",
		"Если волк вас любит он никогда не даст вас в обиду! Он будет обижать вас сам.",
		"Волк — это не волк. Это дух волка, сын волка и волк, волк, волк, волк...",
		"Волк встаёт раньше всех, чтобы не только лишь всех раньше съесть.",
		"Волк сказал — волк укусил — волк налажал — волк супрастин..",
		"Красная шапочка вогнала волка в краску, спросив удивленно, почему у бабули такой огромный хвост...",
	}
	quotesRing *ring.Ring
)

func nextQuote() string {
	auuffff := quotesRing.Value.(string)
	quotesRing = quotesRing.Next()
	return auuffff
}
