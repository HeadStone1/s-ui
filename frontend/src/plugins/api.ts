import axios from 'axios'

const api = axios.create({
    baseURL: './',
})

api.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
api.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest'

const pendingRequests = new Map()
let csrfToken = sessionStorage.getItem('csrfToken') || ''

api.interceptors.request.use(
    (config) => {
        // Generate a unique key for the request
        const requestKey = `${config.method}:${config.url}`
        
        // Check if there is already a pending request with the same key
        if (pendingRequests.has(requestKey)) {
            const cancelSource = pendingRequests.get(requestKey)
            cancelSource.cancel('Duplicate request cancelled')
        }
        
        // Create a new cancel token for the request
        const cancelSource = axios.CancelToken.source()
        config.cancelToken = cancelSource.token
        
        // Store the cancel token in the pending requests map
        pendingRequests.set(requestKey, cancelSource)
        
        if (config.data instanceof FormData) {
            config.headers['Content-Type'] = 'multipart/form-data'
        }
        if (config.method && ['post', 'put', 'delete'].includes(config.method.toLowerCase()) && csrfToken) {
            config.headers['X-CSRF-Token'] = csrfToken
        }
        return config
    },
    (error) => Promise.reject(error),
)

api.interceptors.response.use(
    (response) => {
        const nextCsrfToken = response.headers['x-csrf-token']
        if (nextCsrfToken) {
            csrfToken = nextCsrfToken
            sessionStorage.setItem('csrfToken', csrfToken)
        }
        // Remove the request from the pending requests map
        const requestKey = `${response.config.method}:${response.config.url}`
        pendingRequests.delete(requestKey)
        return response
    },
    (error) => {
        if (axios.isCancel(error)) {
            // Handle duplicate request cancellation here if needed
            console.warn(error.message)
        } else {
            // Remove the request from the pending requests map on error
            const requestKey = `${error.config.method}:${error.config.url}`
            pendingRequests.delete(requestKey)
        }
        return Promise.reject(error)
    }
)

export default api

export const clearCsrfToken = () => {
    csrfToken = ''
    sessionStorage.removeItem('csrfToken')
}
