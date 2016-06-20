package joust

import "net/http"

// Handler is a standard implementation of the middleware
func (j *Joust) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Validate an available token for the request
		_, err := j.ValidateToken(w, r)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

// func (j *Joust) GinHandler(c *gin.Context) {
//
// }
