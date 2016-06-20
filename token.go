package joust

// Identifier allows for a unqiue identity to be provided
type Identifier interface {
	Identity() string
}
