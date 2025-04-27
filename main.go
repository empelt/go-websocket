package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
)

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	// 以下の形式でclientからハンドシェイクのリクエストが来る
	// see https://www.rfc-editor.org/rfc/rfc6455#section-1.3
	// 	 GET /chat HTTP/1.1
	// 	 Host: server.example.com
	// 	 Upgrade: websocket
	// 	 Connection: Upgrade
	// 	 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
	// 	 Origin: http://example.com
	// 	 Sec-WebSocket-Protocol: chat, superchat
	// 	 Sec-WebSocket-Version: 13

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

	// 一旦ここまで
	fmt.Println("WebSocket handshake completed")
}

func main() {
	http.HandleFunc("/ws", websocketHandler)
	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}
