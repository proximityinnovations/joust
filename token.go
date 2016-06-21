package joust

// Identifier allows for a unique identity to be provided
type Identifier interface {
	Identity() string
}
