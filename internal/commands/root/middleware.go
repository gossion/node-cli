package root

//type Middleware func(http.HandlerFunc) http.HandlerFunc

// func MultipleMiddleware(h http.HandlerFunc, m ...Middleware) http.HandlerFunc {

// 	if len(m) < 1 {
// 		return h
// 	}

// 	wrapped := h

// 	// loop in reverse to preserve middleware order
// 	for i := len(m) - 1; i >= 0; i-- {
// 		wrapped = m[i](wrapped)
// 	}

// 	return wrapped
// }

// func LogMiddleware(h http.HandlerFunc) http.HandlerFunc {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

// 		log.SetOutput(os.Stdout) // logs go to Stderr by default
// 		log.Println(r.Method, r.URL)
// 		h.ServeHTTP(w, r) // call ServeHTTP on the original handler

// 	})
// }
