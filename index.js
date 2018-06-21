const { send, json } = require('micro')
const axios = require('axios')
const util = require('util')
const JWT = require('jsonwebtoken')
const { URL } = require('url')

const verifyAsync = util.promisify(JWT.verify)

const grafana = axios.create({ baseURL: process.env.GRAFANA_URL })
const backend = axios.create({ baseURL: process.env.BACKEND_URL })
const JWT_ALGORITHM = process.env.JWT_ALGORITHM
const JWT_PUBLIC = process.env.JWT_PUBLIC
const JWT_SECRET = process.env.JWT_SECRET
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS


module.exports = async (req, res) => {
  const { origin } = req.headers
  const { host, pathName, searchParams } = new URL(req.url)
  const allowed = ALLOWED_ORIGINS.toLowerCase().split(' ')
  if (allowed.includes(origin.toLowerCase())) {
    res.setHeader('access-control-allow-origin', origin)
    res.setHeader('access-control-allow-methods', 'POST, GET')
    res.setHeader('access-control-allow-headers', 'Content-Type, *')
    res.setHeader('access-control-allow-credentials', 'true')
  }
  req.query = searchParams
  if (pathName.match('/healthz')) return { healthy: true }
  if (pathName.match('/find')) return find(req, res)
  if (pathName.match('/render$')) return render(req, res)
  send(res, 404, { error: 'Not found' })
}

async function auth(req) {
  if (!req.headers.authorization) return false
  const [type, value] = req.headers.authorization.split(' ') || []
  if (!type || !value) return false
  if (type !== 'Bearer') return false
  const data = await verifyAsync(value, JWT_PUBLIC || JWT_SECRET, { algorithm: JWT_ALGORITHM })
  if (!data.scope || !data.scope.includes('read:stats')) {
    throw new Error('Unauthorized')
  }
  return data
}

async function find (req, res) {
  let { query: { query } } = req
  if (query === '*' || query === 'screeps') {
    return metricMap(['screeps'], '')
  }
  let orgs = await getOrgs(req)
  let [, user = ''] = query.split('.')
  query = query.replace(user, user.toLowerCase())
  user = user.toLowerCase()
  let valid = orgs.includes(user)
  if (user === '*') {
    let acl = `{${orgs.join(',')}}`
    query = query.replace('screeps.*', `screeps.${acl}`)
    valid = true
  }
  if (valid) {
    let resp = await backend.get('/metrics/find', { params: { query } })
    return resp.data
  } else {
    send(res, 403, { error: 'Forbidden' })
  }
}

async function render (req, res) {
  let orgs = await getOrgs(req)
  let acl = `{${orgs.join(',')}}`
  let body = await json(req)
  body.target = body.target.map(target => {
    let [section, user] = target.split('.')
    let valid = section === 'screeps' && orgs.includes(user)
    if (user === '*') {
      target = target.replace('screeps.*', `screeps.${acl}`)
      valid = true
    }
    return valid ? target : null
  }).filter(a => a)
  let resp = await backend.post('/render', body)
  return resp.data
}

async function getOrgs (req) {
  const user = auth(req)
  if (!user) return []
  // TODO: Get this list dynamically
  return [user.username || user.nickname]
}

function metricMap (list, base) {
  return list.map(item => ({
    id: base ? `${base}.${item}` : item,
    allowChildren: 1,
    expandable: 1,
    leaf: 0,
    text: item
  }))
}
