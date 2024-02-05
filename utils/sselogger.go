package utils

import (
	"fmt"
	"net/http"

	"github.com/mrhaoxx/OpenNG/log"
)

type TextStreamLogger struct {
	notifier       chan []byte
	newClients     chan chan []byte
	closingClients chan chan []byte
	clients        map[chan []byte]bool
}

func NewTextStreamLogger() (broker *TextStreamLogger) {
	broker = &TextStreamLogger{
		notifier:       make(chan []byte, 1),
		newClients:     make(chan chan []byte),
		closingClients: make(chan chan []byte),
		clients:        make(map[chan []byte]bool),
	}
	go broker.listen()
	return
}

func (broker *TextStreamLogger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	flusher, ok := rw.(http.Flusher)

	if !ok {
		http.Error(rw, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Write([]byte("# OpenNG Log Streaming \n\n"))
	messageChan := make(chan []byte)
	broker.newClients <- messageChan
	for {
		select {
		case <-req.Context().Done():
			broker.closingClients <- messageChan
			close(messageChan)
			goto exit
		case msg := <-messageChan:
			rw.Write(msg)
			flusher.Flush()
		}
	}
exit:
}

func (broker *TextStreamLogger) listen() {
	for {
		select {
		case s := <-broker.newClients:
			broker.clients[s] = true
			log.Println(fmt.Sprintf("sys [sselogger] Client added. %d registered clients", len(broker.clients)))
		case s := <-broker.closingClients:
			delete(broker.clients, s)
			log.Println(fmt.Sprintf("sys [sselogger] Removed client. %d registered clients", len(broker.clients)))
		case event := <-broker.notifier:
			for clientMessageChan := range broker.clients {
				clientMessageChan <- event
			}
		}
	}

}

func (b *TextStreamLogger) Write(p []byte) (n int, err error) {
	pCopy := make([]byte, len(p))
	copy(pCopy, p)
	go func() { b.notifier <- pCopy }()
	return len(pCopy), nil
}
