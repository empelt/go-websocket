package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	// 以下の形式でclientからハンドシェイクのリクエストが来る
	// see https://www.rfc-editor.org/rfc/rfc6455#section-1.3
	/*
		GET /chat HTTP/1.1
		Host: server.example.com
		Upgrade: websocket
		Connection: Upgrade
		Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
		Origin: http://example.com
		Sec-WebSocket-Protocol: chat, superchat
		Sec-WebSocket-Version: 13
	*/

	if r.Header.Get("Connection") != "Upgrade" || r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "Not a websocket upgrade request", http.StatusBadRequest)
		return
	}

	secWebSocketKey := r.Header.Get("Sec-WebSocket-Key")
	if secWebSocketKey == "" {
		http.Error(w, "Bad WebSocket handshake", http.StatusBadRequest)
		return
	}

	// acceptKeyの作成
	// Sec-WebSocket-KeyとGUIDを結合したものをSHA1でハッシュ化して、Base64エンコードする
	const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(secWebSocketKey + magicGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", acceptKey)
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	for {
		op, payload, err := readFrame(rw)
		if err != nil {
			fmt.Println("readFrame error:", err)
			return
		}

		fmt.Printf("Received frame: opcode=%d, payload=%s\n", op, string(payload))

		// closeフレームを受信した場合は、closeフレームを返して終了
		if op == 0x8 {
			fmt.Println("Received close frame, closing connection")
			if err := writeCloseFrame(conn, 0x8, "bye"); err != nil {
				fmt.Println("writeFrame error:", err)
				return
			}
			return
		}

		if err := writeFrame(conn, op, payload); err != nil {
			fmt.Println("writeFrame error:", err)
			return
		}
	}
}

func readFrame(r *bufio.ReadWriter) (opcode byte, payload []byte, err error) {
	// 各データフレームは以下の形式で構成されている
	// see https://www.rfc-editor.org/rfc/rfc6455#section-5.2
	/*
			     0                   1                   2                   3
		         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		        +-+-+-+-+-------+-+-------------+-------------------------------+
		        |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
		        |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
		        |N|V|V|V|       |S|             |   (if payload len==126/127)   |
		        | |1|2|3|       |K|             |                               |
		        +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
		        |     Extended payload length continued, if payload len == 127  |
		        + - - - - - - - - - - - - - - - +-------------------------------+
		        |                               |Masking-key, if MASK set to 1  |
		        +-------------------------------+-------------------------------+
		        | Masking-key (continued)       |          Payload Data         |
		        +-------------------------------- - - - - - - - - - - - - - - - +
		        :                     Payload Data continued ...                :
		        + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
		        |                     Payload Data continued ...                |
		        +---------------------------------------------------------------+
	*/

	const (
		finBit    = 1 << 7
		maskedBit = 1 << 7
	)

	// 必須の先頭2バイトを読む
	header := make([]byte, 2)
	if _, err = io.ReadFull(r, header); err != nil {
		return
	}

	fin := (header[0] & finBit) != 0
	opcode = header[0] & 0x0F // 0x0F = 00001111
	masked := (header[1] & maskedBit) != 0
	payloadLen := int(header[1] & 0x7F) // 0x7F = 01111111

	// opcodeは、0x0~0x7がテキストフレーム、0x8がcloseフレーム、0x9がpingフレーム、0xAがpongフレーム
	// closeフレームを受信した場合は、ここで終了
	if opcode == 0x8 {
		return
	}

	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		// example:
		//   ext[0] = 00000001 = 1
		//   ext[1] = 01111110 = 126
		//   payloadLen = 1<<8 | 126 = 256 + 126 = 382
		payloadLen = int(ext[0])<<8 | int(ext[1])
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		// 一旦4GB超のデータは無視
		payloadLen = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}

	var maskingKey []byte
	if masked {
		maskingKey = make([]byte, 4)
		if _, err = io.ReadFull(r, maskingKey); err != nil {
			return
		}
	}

	payload = make([]byte, payloadLen)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}

	if masked {
		for i := range payloadLen {
			payload[i] ^= maskingKey[i%4]
		}
	}

	if !fin {
		// 一旦、フラグメント化されたフレームは無視
		err = fmt.Errorf("fragmented frames not supported yet")
	}

	return
}

func writeCloseFrame(w io.Writer, code int, reason string) error {
	payload := make([]byte, 2+len(reason))
	payload[0] = byte(code >> 8)
	payload[1] = byte(code)

	copy(payload[2:], reason)

	return writeFrame(w, 0x8, payload)
}

func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	// 送信時はマスクしないため、Finとopcodeのみをセット
	header := []byte{0x80 | opcode}

	payloadLen := len(payload)
	if payloadLen < 126 {
		header = append(header, byte(payloadLen))
	} else if payloadLen <= 0xFFFF {
		header = append(header, 126, byte(payloadLen>>8), byte(payloadLen))
	} else {
		header = append(header, 127,
			0, 0, 0, 0, // 上位32bit無視
			byte(payloadLen>>24), byte(payloadLen>>16), byte(payloadLen>>8), byte(payloadLen))
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}

func main() {
	http.HandleFunc("/ws", websocketHandler)
	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}
