const { send, json } = require('micro')
const axios = require('axios')
const util = require('util')
const JWT = require('jsonwebtoken')

const verifyAsync = util.promisify(JWT.verify)

const grafana = axios.create({ baseURL: process.env.GRAFANA_URL })
const backend = axios.create({ baseURL: process.env.BACKEND_URL })
const JWT_ALGORITHM = process.env.JWT_ALGORITHM
const JWT_PUBLIC = process.env.JWT_PUBLIC
const JWT_SECRET = process.env.JWT_SECRET

module.exports = async (req, res) => {
  if (req.url.match('/healthz')) return { healthy: true }
  if (req.url.match('/find$')) return find(req, res)
  if (req.url.match('/render$')) return render(req, res)
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
  return [user.prefered_username || user.username || user.nickname]
  let { data: orgs } = await grafana.get('/api/user/orgs', { headers: { 'Cookie': cookie } })
  return orgs.map(o => o.Name.toLowerCase())
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
