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

// // GinHandler is a middleware implementation for the gin library
// func GinHandler(j *Joust) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		// Validate an available token for the request
// 		token, err := j.ValidateToken(c.Writer, c.Request)
// 		// If there was an error, do not continue.
// 		if err != nil {
// 			return
// 		}
//
// 		// Set the id of the user
// 		c.Set(j.Options.IdentityProperty, token.Claims.(jwt.StandardClaims).Id)
// 	}
// }
