package messaging

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrMessageNotFound   = errors.New("message not found")
	ErrRecipientNotFound = errors.New("recipient not found")
	ErrMessageTooLarge   = errors.New("message payload too large")
	ErrInvalidCiphertext = errors.New("invalid ciphertext format")
)

// MaxPayloadBytes - max size of an encrypted message payload (1MB)
const MaxPayloadBytes = 1 * 1024 * 1024

// Message is what gets stored and relayed
// IMPORTANT: server never decrypts Ciphertext
type Message struct {
	ID           uuid.UUID  `json:"id"`
	SenderID     uuid.UUID  `json:"sender_id"`
	RecipientID  uuid.UUID  `json:"recipient_id"`
	EphemeralKey string     `json:"ephemeral_key"` // base64 X25519 public key
	Nonce        string     `json:"nonce"`         // base64 12 bytes
	Ciphertext   string     `json:"ciphertext"`    // base64 ChaCha20-Poly1305 output
	SentAt       time.Time  `json:"sent_at"`
	DeliveredAt  *time.Time `json:"delivered_at,omitempty"`
}

// SendInput from client over WebSocket
type SendInput struct {
	RecipientID  string `json:"recipient_id" validate:"required,uuid"`
	EphemeralKey string `json:"ephemeral_key" validate:"required"`
	Nonce        string `json:"nonce" validate:"required"`
	Ciphertext   string `json:"ciphertext" validate:"required"`
}

// DeliveryAck sent from recipient back to server
type DeliveryAck struct {
	MessageID string `json:"message_id"`
}

// Service defines messaging business logic
type Service interface {
	Send(ctx context.Context, senderID uuid.UUID, input SendInput) (*Message, error)
	GetPendingMessages(ctx context.Context, userID uuid.UUID) ([]*Message, error)
	AcknowledgeDelivery(ctx context.Context, userID uuid.UUID, messageID uuid.UUID) error
}

// Repository defines storage contract for messages
type Repository interface {
	Save(ctx context.Context, msg *Message) error
	FindPending(ctx context.Context, recipientID uuid.UUID) ([]*Message, error)
	MarkDelivered(ctx context.Context, messageID uuid.UUID, deliveredAt time.Time) error
}

// Hub manages active WebSocket connections
// Each connected client registers here; messages are fanned out via channels
type Hub interface {
	Register(conn Connection)
	Unregister(conn Connection)
	Send(recipientID uuid.UUID, msg *Message) bool // returns false if user is offline
}

// Connection represents a single WebSocket client connection
type Connection interface {
	UserID() uuid.UUID
	Send(msg *Message) error
	Close() error
}
