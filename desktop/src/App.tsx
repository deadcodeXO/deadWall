import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react"
import { invoke } from "@tauri-apps/api/core"
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Bell,
  Cpu,
  Globe2,
  List,
  Moon,
  Network,
  Settings as Gear,
  Shield,
  Sun,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  applyPalette,
  defaultPalette,
  palettes,
  type Palette,
} from "./palettes"
import "./deadwall.css"

type Point = {
  end: number
  first: number
  duration: number
  rx: number
  tx: number
}
type Flow = {
  host: string
  remote: string
  local: string
  app?: string
  path?: string
  country?: string
  type: string
  rx: number
  tx: number
}
type Sample = { point: Point; rows: Flow[]; other: { rx: number; tx: number } }
type Usage = { label: string; path?: string; rx: number; tx: number }
type Proc = {
  pid: number
  name: string
  path?: string
  cpu: number
  memory: number
  disk: number
  gpu?: number
}
type Device = { address: string; mac: string; interface: string }
type Resource = {
  cpu: number
  memory: number
  capacity: number
  gpu?: number
  disk?: number
  processes: Proc[]
}
type Nation = {
  code: string
  name: string
  continent: string
  latitude: number | null
  longitude: number | null
}
type Spec = { continents: string[]; countries: string; cidrs: string }
type Note = { time: number; title: string; detail: string }
type Source = { key: string; name: string; kind: string }
type Profile = { id: string; name: string; categories: number; apps: string[] }

type Outcome<T> = { Ok: T } | { Err: string }
type Update =
  | { kind: "sample"; data: Sample }
  | { kind: "selected"; data: string | null }
  | { kind: "sources"; data: { list: Source[]; warning: string | null } }
  | { kind: "state" | "storage" | "notice"; data: string }
  | { kind: "alert"; data: Note }
  | { kind: "resources"; data: Resource }
  | { kind: "devices"; data: Outcome<Device[]> }
  | { kind: "filter"; data: Outcome<number> }
  | { kind: "history"; data: { id: number; result: Outcome<Point[]> } }
  | { kind: "usage"; data: { id: number; result: Outcome<Usage[]> } }
const emptySpec: Spec = { continents: [], countries: "", cidrs: "" }
import countryData from "../../assets/country-metadata.json"
const metadata: Record<string, Omit<Nation, "code">> = countryData
const periods = [
  ["Live", 120, 1000],
  ["1 hour", 3600, 5000],
  ["24 hours", 86400, 120000],
  ["7 days", 604800, 900000],
  ["All time", 0, 1000],
] as const
const dimensions = ["App", "Host", "Traffic type", "Connection", "Country"]
const pages = [
  ["Traffic", Activity],
  ["Firewall", Shield],
  ["Alerts", Bell],
  ["Things", Network],
  ["Hardware", Cpu],
  ["Settings", Gear],
] as const
const continents = [
  ["AF", "Africa"],
  ["AS", "Asia"],
  ["EU", "Europe"],
  ["NA", "North America"],
  ["OC", "Oceania"],
  ["SA", "South America"],
  ["AN", "Antarctica"],
]
const time = (stamp: number) => new Date(stamp).toLocaleTimeString()
const amount = (bytes: number) =>
  bytes < 1024
    ? `${Math.round(bytes)} B`
    : bytes < 1048576
      ? `${(bytes / 1024).toFixed(1)} KiB`
      : bytes < 1073741824
        ? `${(bytes / 1048576).toFixed(1)} MiB`
        : `${(bytes / 1073741824).toFixed(2)} GiB`
function read<T>(name: string, fallback: T): T {
  try {
    return JSON.parse(localStorage.getItem(name) ?? "null") ?? fallback
  } catch {
    return fallback
  }
}
const write = (name: string, value: unknown) =>
  localStorage.setItem(name, JSON.stringify(value))
const blankResource: Resource = {
  cpu: 0,
  memory: 0,
  capacity: 0,
  processes: [],
}
const cmd = (action: string, params: Record<string, unknown> = {}) =>
  invoke("monitor", { action, options: params })
const nation = (code: string) =>
  metadata[code]?.name || code || "Unlocated / local"

const paletteIds = Object.keys(palettes) as Palette[]
const currentPalette = (): Palette => {
  const preferred = read<string>("palette", defaultPalette)
  return paletteIds.find((id) => id === preferred) ?? defaultPalette
}

function useAppearance() {
  const [dark, setDark] = useState(() => read<boolean>("dark", false) === true)
  const [palette, setPalette] = useState(currentPalette)
  useLayoutEffect(() => {
    applyPalette(document.documentElement, palette, dark)
  }, [dark, palette])
  useEffect(() => {
    function sync(event: StorageEvent) {
      if (event.key === "dark" || event.key === null)
        setDark(read<boolean>("dark", false) === true)
      if (event.key === "palette" || event.key === null)
        setPalette(currentPalette())
    }
    window.addEventListener("storage", sync)
    return () => window.removeEventListener("storage", sync)
  }, [])
  return {
    dark,
    palette,
    toggleMode: () => {
      write("dark", !dark)
      setDark(!dark)
    },
    choosePalette: (value: Palette) => {
      write("palette", value)
      setPalette(value)
    },
  }
}
function Chart({
  points,
  grid = true,
  selected,
  onPick,
  small = false,
}: {
  points: Point[]
  grid?: boolean
  selected?: number
  onPick?: (point: Point) => void
  small?: boolean
}) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const [hover, setHover] = useState<Point>()
  const [size, setSize] = useState({ width: 0, height: 0 })
  useEffect(() => {
    const el = canvas.current
    if (!el) return
    const watcher = new ResizeObserver(([entry]) =>
      setSize({
        width: entry.contentRect.width,
        height: entry.contentRect.height,
      })
    )
    watcher.observe(el)
    return () => watcher.disconnect()
  }, [])
  const { width, height } = size,
    left = small ? 4 : 70,
    bottom = height - (small ? 4 : 30)
  const from = points[0]?.end ?? 0,
    to = points.at(-1)?.end ?? 0
  const x = (p: Point) =>
    from === to
      ? width - 10
      : left + ((p.end - from) / (to - from)) * (width - left - 10)
  const rates = (p: Point) =>
    [p.rx, p.tx].map((value) => (value * 1000) / Math.max(1, p.duration))
  const max = Math.max(1024, ...points.flatMap(rates)) * 1.12
  useEffect(() => {
    const element = canvas.current,
      ctx = element?.getContext("2d")
    if (!element || !ctx || width <= left || height <= 36) return
    const dpr = devicePixelRatio
    element.width = Math.round(width * dpr)
    element.height = Math.round(height * dpr)
    ctx.scale(dpr, dpr)
    const tokens = getComputedStyle(document.documentElement)
    ctx.font = "11px Inter, sans-serif"
    ctx.fillStyle = tokens.getPropertyValue("--quiet").trim()
    ctx.textAlign = "right"
    if (!small)
      for (let steps = 0; steps <= 4; steps++) {
        const y = bottom - ((bottom - 10) * steps) / 4
        if (grid) {
          ctx.strokeStyle = tokens.getPropertyValue("--stroke").trim()
          ctx.beginPath()
          ctx.moveTo(left, y)
          ctx.lineTo(width - 10, y)
          ctx.stroke()
        }
        ctx.fillText(amount((max * steps) / 4) + "/s", left - 8, y + 4)
      }
    const colors = ["--dw-accent", "--purple"].map((key) =>
      tokens.getPropertyValue(key).trim()
    )
    for (let channel = 0; channel < 2; channel++) {
      if (!points.length) break
      const y = (p: Point) => bottom - (rates(p)[channel] / max) * (bottom - 10)
      ctx.beginPath()
      ctx.moveTo(x(points[0]), y(points[0]))
      for (let i = 1; i < points.length; i++) {
        const previous = points[i - 1]
        const current = points[i]
        const start = x(previous)
        const end = x(current)
        const handle = (end - start) / 3
        ctx.bezierCurveTo(
          start + handle,
          y(previous),
          end - handle,
          y(current),
          end,
          y(current)
        )
      }
      if (points.length === 1) {
        ctx.beginPath()
        ctx.arc(x(points[0]), y(points[0]), 2, 0, Math.PI * 2)
        ctx.fillStyle = colors[channel]
        ctx.fill()
        continue
      }
      ctx.strokeStyle = colors[channel]
      ctx.lineWidth = 1.7
      ctx.stroke()
      ctx.lineTo(x(points.at(-1)!), bottom)
      ctx.lineTo(x(points[0]), bottom)
      ctx.closePath()
      const gradient = ctx.createLinearGradient(0, 12, 0, bottom)
      gradient.addColorStop(0, colors[channel] + "85")
      gradient.addColorStop(1, colors[channel] + "35")
      ctx.fillStyle = gradient
      ctx.fill()
    }
    if (!small && points.length > 1) {
      ctx.fillStyle = tokens.getPropertyValue("--quiet").trim()
      const intervals = width < 500 ? 2 : 4
      for (let i = 0; i <= intervals; i++) {
        const t = i / intervals
        ctx.textAlign = i === intervals ? "right" : i === 0 ? "left" : "center"
        ctx.fillText(
          time(from + t * (to - from)),
          left + t * (width - left - 10),
          height - 9
        )
      }
    }
    const marker = hover || points.find((p) => p.end === selected)
    if (marker) {
      ctx.strokeStyle = tokens.getPropertyValue("--chart-marker").trim()
      ctx.beginPath()
      ctx.moveTo(x(marker), 4)
      ctx.lineTo(x(marker), bottom)
      ctx.stroke()
      if (!small) {
        rates(marker).forEach((rate, channel) => {
          ctx.fillStyle = colors[channel]
          ctx.beginPath()
          ctx.arc(
            x(marker),
            bottom - (rate / max) * (bottom - 10),
            3.5,
            0,
            Math.PI * 2
          )
          ctx.fill()
        })
      }
    }
  })
  function nearest(event: React.MouseEvent) {
    const offset =
      event.clientX - event.currentTarget.getBoundingClientRect().left
    return points.reduce<Point | undefined>(
      (a, p) =>
        !a || Math.abs(x(p) - offset) < Math.abs(x(a) - offset) ? p : a,
      undefined
    )
  }
  return (
    <div className={small ? "chart mini-chart" : "chart"}>
      <canvas
        ref={canvas}
        onMouseMove={(e) => setHover(nearest(e))}
        onMouseLeave={() => setHover(undefined)}
        onClick={(e) => {
          const p = nearest(e)
          if (p) onPick?.(p)
        }}
        aria-label="Bandwidth graph"
      />
      {hover && !small && (
        <div className="chartTip">
          {time(hover.end)} · ↓ {amount(rates(hover)[0])}/s · ↑{" "}
          {amount(rates(hover)[1])}/s
        </div>
      )}
    </div>
  )
}

function MapView({
  samples,
  history,
  live,
  seconds,
  now,
  dark,
  onNotice,
}: {
  samples: Sample[]
  history: Usage[]
  live: boolean
  seconds: number
  now: number
  dark: boolean
  onNotice: (x: string) => void
}) {
  const [selected, setSelected] = useState("")
  const [hover, setHover] = useState("")
  const [ip, setIp] = useState("")
  const [pin, setPin] = useState<Nation | null>(null)
  const [zoom, setZoom] = useState(1)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const drag = useRef<{ x: number; y: number } | null>(null)
  const markers = useMemo(() => {
    const grouped = new Map<
      string,
      { total: number; peers: Map<string, Flow & { seen: number }> }
    >()
    if (live) {
      for (const sample of samples.filter(
        (s) => s.point.end >= now - seconds * 1000
      )) {
        for (const row of sample.rows) {
          if (!row.country || !metadata[row.country]) continue
          let info = grouped.get(row.country)
          if (!info) {
            info = { total: 0, peers: new Map() }
            grouped.set(row.country, info)
          }
          const old = info.peers.get(row.host)
          info.total += row.rx + row.tx
          info.peers.set(row.host, {
            ...row,
            rx: row.rx + (old?.rx || 0),
            tx: row.tx + (old?.tx || 0),
            seen: sample.point.end,
          })
        }
      }
    } else
      for (const row of history) {
        if (metadata[row.label])
          grouped.set(row.label, { total: row.rx + row.tx, peers: new Map() })
      }
    return grouped
  }, [samples, history, live, seconds, now])
  const active = hover || selected,
    info = markers.get(active)
  return (
    <section className="card">
      <div className="toolbar">
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            try {
              const result = await invoke<Nation | null>("locate", {
                address: ip.trim(),
              })
              setPin(result)
              if (!result) onNotice("No country match for this address.")
            } catch (e) {
              onNotice(String(e))
            }
          }}
        >
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="IPv4 or IPv6 address"
          />
          <Button variant="outline">Look up</Button>
        </form>
        <Button
          variant="outline"
          onClick={() => {
            setZoom(1)
            setOffset({ x: 0, y: 0 })
            setSelected("")
            setPin(null)
          }}
        >
          Reset map
        </Button>
      </div>
      <div
        className="world"
        onWheel={(event) =>
          setZoom((value) =>
            Math.max(1, Math.min(5, value + (event.deltaY < 0 ? 0.2 : -0.2)))
          )
        }
        onPointerDown={(event) => {
          if ((event.target as HTMLElement).closest("button")) return
          drag.current = {
            x: event.clientX - offset.x,
            y: event.clientY - offset.y,
          }
          event.currentTarget.setPointerCapture(event.pointerId)
        }}
        onPointerMove={(event) => {
          if (drag.current)
            setOffset({
              x: event.clientX - drag.current.x,
              y: event.clientY - drag.current.y,
            })
        }}
        onPointerUp={() => {
          drag.current = null
        }}
      >
        <div
          className="mapSheet"
          style={{
            transform: `translate(${offset.x}px,${offset.y}px) scale(${zoom})`,
          }}
        >
          <img
            draggable="false"
            src={dark ? "/world-dark.png" : "/world-light.png"}
            alt="World map"
          />
          {[...markers].map(([code, group]) => {
            const place = metadata[code]
            if (place.latitude == null || place.longitude == null) return null
            return (
              <button
                key={code}
                className={active === code ? "dot active" : "dot"}
                style={{
                  left: `${(place.longitude + 180) / 3.6}%`,
                  top: `${(90 - place.latitude) / 1.8}%`,
                }}
                aria-label={`${place.name}, ${group.peers.size} IPs`}
                onMouseEnter={() => setHover(code)}
                onMouseLeave={() => setHover("")}
                onFocus={() => setHover(code)}
                onBlur={() => setHover("")}
                onClick={() =>
                  setSelected((current) => (current === code ? "" : code))
                }
              />
            )
          })}
          {pin?.latitude != null && pin.longitude != null && (
            <span
              className="dot pin"
              style={{
                left: `${(pin.longitude + 180) / 3.6}%`,
                top: `${(90 - pin.latitude) / 1.8}%`,
              }}
            />
          )}
        </div>
        {info && (
          <aside className="mapTip">
            <strong>{nation(active)}</strong>
            <small>
              {amount(info.total)} · {info.peers.size} observed IPs
            </small>
            {[...info.peers.values()]
              .sort((a, b) => b.rx + b.tx - a.rx - a.tx)
              .slice(0, 7)
              .map((p) => (
                <div key={p.host}>
                  <b>{p.remote}</b>
                  <small>
                    {p.app || "Unknown app"} · {p.type} · ↓ {amount(p.rx)} ↑{" "}
                    {amount(p.tx)} · {time(p.seen)}
                  </small>
                </div>
              ))}
          </aside>
        )}
      </div>
      <div className="mapFoot">
        {pin
          ? `${ip} · ${pin.name}`
          : "Country estimates · drag to pan and scroll to zoom"}{" "}
        <span>DB-IP · CC BY 4.0 · Natural Earth</span>
      </div>
    </section>
  )
}

function Mini() {
  useAppearance()
  const [points, setPoints] = useState<Point[]>([])
  useEffect(() => {
    const read = () =>
      invoke<Point[]>("mini_points")
        .then(setPoints)
        .catch(() => {})
    void read()
    const timer = setInterval(read, 1000)
    return () => clearInterval(timer)
  }, [])
  return (
    <div className="mini">
      <strong>Live bandwidth</strong>
      <Chart points={points} small />
    </div>
  )
}

function Dashboard() {
  const { dark, palette, toggleMode, choosePalette } = useAppearance()
  const [now, setNow] = useState(Date.now)
  const [page, setPage] = useState("Traffic"),
    [view, setView] = useState("Timeline")
  const [samples, setSamples] = useState<Sample[]>([]),
    [sources, setSources] = useState<Source[]>([]),
    [source, setSource] = useState("")
  const [status, setStatus] = useState("Starting monitor"),
    [notice, setNotice] = useState(""),
    [storage, setStorage] = useState(""),
    [paused, setPaused] = useState(false)
  const [resources, setResources] = useState<Resource>(blankResource),
    [alerts, setAlerts] = useState<Note[]>([])
  const [devices, setDevices] = useState<Device[]>([]),
    [scanSources, setScanSources] = useState<string[]>([]),
    [scanSource, setScanSource] = useState(""),
    [scanning, setScanning] = useState(false)
  const [range, setRange] = useState(0),
    [group, setGroup] = useState(0),
    [historical, setHistorical] = useState<Point[]>([]),
    [historyUsage, setHistoryUsage] = useState<Usage[]>([])
  const [picked, setPicked] = useState<Point>(),
    [search, setSearch] = useState("")
  const [liveMap, setLiveMap] = useState(true),
    [mapSeconds, setMapSeconds] = useState(() => read("mapSeconds", 30)),
    [grid, setGrid] = useState(() => read("grid", true))
  const [inspector, setInspector] = useState(() => read("inspector", false))
  const [trayEnabled, setTrayEnabled] = useState(() =>
    read("minimizeToTray", false)
  )
  const [trayPending, setTrayPending] = useState(false)
  const [profileBits, setProfileBits] = useState(7),
    [firewallTab, setFirewallTab] = useState("Processes")
  const [profiles, setProfiles] = useState<Profile[]>([]),
    [profileName, setProfileName] = useState(""),
    [paths, setPaths] = useState(""),
    [manualPath, setManualPath] = useState("")
  const [requests, setRequests] = useState<{
    active: boolean
    requests: string[]
  }>({ active: false, requests: [] })
  const [menu, setMenu] = useState<{ x: number; y: number; process: Proc }>()
  const [spec, setSpec] = useState<Spec>(() => read("geoRules", emptySpec)),
    [filters, setFilters] = useState(0)
  const [filterPending, setFilterPending] = useState(false)
  const [firewallBusy, setFirewallBusy] = useState(false)
  const [resourceHistory, setResourceHistory] = useState<Resource[]>([])
  const queryId = useRef(0)
  const workspace = useRef<HTMLDivElement>(null)
  const fail = (error: unknown) => setNotice(String(error))
  const since = () =>
    periods[range][1] ? Date.now() - periods[range][1] * 1000 : 0
  const send = (action: string, args: Record<string, unknown> = {}) =>
    cmd(action, args).catch(fail)
  useEffect(() => {
    let mounted = true
    if (read("minimizeToTray", false)) {
      void invoke("set_minimize_to_tray", { enabled: true }).catch((error) => {
        if (mounted) {
          setTrayEnabled(false)
          write("minimizeToTray", false)
          setNotice(String(error))
        }
      })
    }
    return () => {
      mounted = false
    }
  }, [])
  async function changeTray(enabled: boolean) {
    setTrayPending(true)
    try {
      await invoke("set_minimize_to_tray", { enabled })
      write("minimizeToTray", enabled)
      setTrayEnabled(enabled)
    } catch (error) {
      fail(error)
    } finally {
      setTrayPending(false)
    }
  }
  useEffect(() => {
    write("inspector", inspector)
    write("grid", grid)
    write("mapSeconds", mapSeconds)
    write("geoRules", spec)
  }, [inspector, grid, mapSeconds, spec])
  useEffect(() => {
    let stopped = false,
      active = false
    async function next() {
      if (active || stopped) return
      active = true
      try {
        const events = await invoke<Update[]>("poll")
        if (!stopped) setNow(Date.now())
        if (stopped) return
        for (const { kind, data } of events) {
          switch (kind) {
            case "sample":
              setSamples((old) => [...old, data].slice(-120))
              break
            case "selected":
              setSamples([])
              setHistorical([])
              setHistoryUsage([])
              setPicked(undefined)
              setSource(data || "")
              break
            case "sources":
              setSources(data.list)
              if (data.warning) setNotice(data.warning)
              break
            case "state":
              setStatus(data)
              break
            case "storage":
              setStorage(data)
              break
            case "notice":
              setNotice(data)
              break
            case "alert":
              setAlerts((old) => [data, ...old].slice(0, 500))
              break
            case "resources":
              setResources(data)
              setResourceHistory((old) => [...old, data].slice(-60))
              break
            case "devices":
              if ("Ok" in data) setDevices(data.Ok)
              else setNotice(data.Err)
              break
            case "filter":
              setFilterPending(false)
              if ("Ok" in data) {
                setFilters(data.Ok)
                setNotice(
                  data.Ok
                    ? `Geographic filters active · ${data.Ok} ranges`
                    : "Geographic filters cleared"
                )
              } else setNotice(data.Err)
              break
            case "history":
              if (data.id === queryId.current) {
                if ("Ok" in data.result) setHistorical(data.result.Ok)
                else setNotice(data.result.Err)
              }
              break
            case "usage":
              if (data.id === queryId.current) {
                if ("Ok" in data.result) setHistoryUsage(data.result.Ok)
                else setNotice(data.result.Err)
              }
              break
          }
        }
      } catch (error) {
        if (!stopped) setNotice(String(error))
      } finally {
        active = false
      }
    }
    void next()
    const id = setInterval(next, 500)
    return () => {
      stopped = true
      clearInterval(id)
    }
  }, [])
  useEffect(() => {
    if (!source || !range) return
    const id = ++queryId.current,
      from = since()
    void send("history", { id, from, width: periods[range][2] })
    void send("usage", {
      id,
      from: picked?.first ?? from,
      to: picked?.end,
      group: view === "IP map" ? 4 : group,
    })
    // A new query ID prevents a previous range or group from updating the display.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, range, group, picked, view])
  useEffect(() => {
    if (page === "Things")
      invoke<string[]>("scan_sources").then(setScanSources).catch(fail)
    if (page === "Firewall")
      invoke<Profile[]>("profile", { action: "list" })
        .then(setProfiles)
        .catch(fail)
  }, [page])
  useEffect(() => {
    if (page !== "Firewall" || firewallTab !== "Connection modes") return
    const refresh = () =>
      invoke<typeof requests>("approval", { action: "list" })
        .then(setRequests)
        .catch(fail)
    void refresh()
    const timer = setInterval(refresh, 1500)
    return () => clearInterval(timer)
  }, [page, firewallTab])
  const points = range ? historical : samples.map((s) => s.point)
  const total = (picked ? [picked] : points).reduce(
    (sum, p) => ({ rx: sum.rx + p.rx, tx: sum.tx + p.tx }),
    { rx: 0, tx: 0 }
  )
  const usage = useMemo(() => {
    if (range) return historyUsage
    const rows = new Map<string, Usage>()
    const g = view === "IP map" ? 4 : group
    for (const sample of samples) {
      if (picked && sample.point.end !== picked.end) continue
      if (sample.other.rx || sample.other.tx) {
        const old = rows.get("Other flows") || {
          label: "Other flows",
          rx: 0,
          tx: 0,
        }
        rows.set("Other flows", {
          ...old,
          rx: old.rx + sample.other.rx,
          tx: old.tx + sample.other.tx,
        })
      }
      for (const flow of sample.rows) {
        const label = [
          flow.app || "Unknown app",
          flow.host,
          flow.type,
          `${flow.local} ↔ ${flow.remote}`,
          flow.country || "",
        ][g]
        const path = g === 0 ? flow.path : undefined
        const key = JSON.stringify([label, path]),
          old = rows.get(key)
        rows.set(key, {
          label,
          path,
          rx: flow.rx + (old?.rx || 0),
          tx: flow.tx + (old?.tx || 0),
        })
      }
    }
    return [...rows.values()].sort((a, b) => b.rx + b.tx - a.rx - a.tx)
  }, [samples, range, historyUsage, group, view, picked])
  async function firewallChange(blocked: boolean, path?: string) {
    if (!profileBits || firewallBusy) return
    setFirewallBusy(true)
    try {
      setNotice(
        await invoke<string>("firewall_change", {
          path,
          profiles: profileBits,
          blocked,
        })
      )
    } catch (error) {
      fail(error)
    } finally {
      setFirewallBusy(false)
      setMenu(undefined)
    }
  }
  async function profile(action: string, id?: string) {
    setFirewallBusy(true)
    try {
      setProfiles(
        await invoke<Profile[]>("profile", {
          action,
          id,
          name: profileName,
          categories: profileBits,
          paths,
        })
      )
      if (action === "save") {
        setProfileName("")
        setPaths("")
      }
    } catch (error) {
      fail(error)
    } finally {
      setFirewallBusy(false)
    }
  }
  async function approval(action: string, index?: number) {
    try {
      setRequests(await invoke<typeof requests>("approval", { action, index }))
    } catch (error) {
      fail(error)
    }
  }
  async function applyGeo(next: Spec) {
    setFilterPending(true)
    try {
      await invoke("geographic_filter", { spec: next })
    } catch (error) {
      setFilterPending(false)
      fail(error)
    }
  }
  async function discover() {
    if (!scanSource) return
    setScanning(true)
    try {
      const list = await invoke<Device[]>("scan", { source: scanSource })
      setDevices((old) => [
        ...old.filter((d) => !list.some((n) => n.address === d.address)),
        ...list,
      ])
      setNotice(`Discovered ${list.length} LAN devices`)
    } catch (error) {
      fail(error)
    } finally {
      setScanning(false)
    }
  }
  const matches = (value: string) =>
    value.toLowerCase().includes(search.trim().toLowerCase())
  const processRows = resources.processes
    .filter(
      (p) => matches(p.name) || matches(String(p.pid)) || matches(p.path || "")
    )
    .sort((a, b) =>
      page === "Hardware"
        ? b.cpu - a.cpu
        : a.name.localeCompare(b.name) || a.pid - b.pid
    )
  function changePage(next: string) {
    workspace.current?.scrollTo({ top: 0 })
    setPage(next)
    setSearch("")
    setMenu(undefined)
  }
  return (
    <div
      className="shell"
      onClick={() => menu && setMenu(undefined)}
      onKeyDown={(e) => {
        if (e.key === "Escape") setMenu(undefined)
      }}
    >
      <header className="top">
        <button
          type="button"
          className="brand"
          aria-label="deadWall home"
          onClick={() => {
            setView("Timeline")
            setPicked(undefined)
            changePage("Traffic")
          }}
        >
          <img src="/deadwall.png" alt="" />
          deadWall
        </button>
        <nav aria-label="Main navigation">
          {pages.map(([name, Icon]) => (
            <Button
              key={name}
              variant={page === name ? "secondary" : "ghost"}
              onClick={() => changePage(name)}
            >
              <Icon size={17} />
              {name}
            </Button>
          ))}
        </nav>
        <Button
          className="theme"
          variant="outline"
          size="icon"
          aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
          onClick={toggleMode}
        >
          {dark ? <Sun /> : <Moon />}
        </Button>
      </header>
      <div
        ref={workspace}
        className="workspaceViewport"
        onScroll={() => {
          if (menu) setMenu(undefined)
        }}
        role="region"
        aria-label="Dashboard"
        tabIndex={0}
      >
        <div className="workspace">
          <div className="toolbar status">
            <span>
              <i className={paused ? "paused" : ""} />
              {sources.find((s) => s.key === source)?.name || status}
            </span>
            <div>
              <Button
                variant="ghost"
                onClick={() => invoke("mini").catch(fail)}
              >
                Mini graph
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setPaused(!paused)
                  void send("pause", { paused: !paused })
                }}
              >
                {paused ? "Resume" : "Pause"}
              </Button>
              <Button
                variant={inspector ? "secondary" : "ghost"}
                onClick={() => setInspector(!inspector)}
              >
                Inspector
              </Button>
            </div>
          </div>
          {notice && (
            <div className="notice" role="status">
              {notice}
              <button aria-label="Dismiss notice" onClick={() => setNotice("")}>
                ×
              </button>
            </div>
          )}
          <div className="body">
            <main className="panel">
              {page === "Traffic" && (
                <>
                  <div className="toolbar sectionTitle">
                    <h1>Network traffic</h1>
                    <div
                      className="trafficViews"
                      role="group"
                      aria-label="Traffic view"
                    >
                      {[
                        { label: "Timeline", Icon: Activity },
                        { label: "Table", Icon: List },
                        { label: "IP map", Icon: Globe2 },
                      ].map(({ label, Icon }) => (
                        <Button
                          key={label}
                          variant={view === label ? "secondary" : "ghost"}
                          aria-pressed={view === label}
                          onClick={() => {
                            setView(label)
                            setSearch("")
                          }}
                        >
                          <Icon size={15} /> {label}
                        </Button>
                      ))}
                    </div>
                    <div>
                      <select
                        aria-label="Time range"
                        value={range}
                        onChange={(e) => {
                          setRange(Number(e.target.value))
                          setPicked(undefined)
                          setHistorical([])
                          setHistoryUsage([])
                        }}
                      >
                        {periods.map(([label], index) => (
                          <option key={label} value={index}>
                            {label}
                          </option>
                        ))}
                      </select>
                      <Button
                        variant="outline"
                        onClick={() => void send("export", { from: since() })}
                      >
                        Export CSV
                      </Button>
                    </div>
                  </div>
                  {view === "Timeline" && (
                    <section className="card plot">
                      <div className="legend">
                        <span>Received</span>
                        <span>Sent</span>
                      </div>
                      {points.length === 0 && (
                        <p className="chartEmpty">
                          No traffic in this range yet
                        </p>
                      )}
                      <Chart
                        points={points}
                        grid={grid}
                        selected={picked?.end}
                        onPick={setPicked}
                      />
                    </section>
                  )}
                  {view === "IP map" && (
                    <>
                      <div className="toolbar">
                        <label>
                          <input
                            type="checkbox"
                            checked={liveMap}
                            onChange={(e) => setLiveMap(e.target.checked)}
                          />{" "}
                          Live connections
                        </label>
                      </div>
                      <MapView
                        samples={samples}
                        history={usage}
                        live={liveMap}
                        seconds={mapSeconds}
                        now={now}
                        dark={dark}
                        onNotice={setNotice}
                      />
                    </>
                  )}
                  <div className="totals card">
                    <div>
                      <small>
                        <ArrowDown size={14} /> Received
                      </small>
                      <strong>{amount(total.rx)}</strong>
                    </div>
                    <div>
                      <small>
                        <ArrowUp size={14} /> Sent
                      </small>
                      <strong>{amount(total.tx)}</strong>
                    </div>
                    <div>
                      <small>
                        {picked ? "Selected total" : "Total traffic"}
                      </small>
                      <strong>{amount(total.rx + total.tx)}</strong>
                      <div className="trafficMix" aria-hidden="true">
                        <span style={{ flexGrow: total.rx }} />
                        <span style={{ flexGrow: total.tx }} />
                      </div>
                    </div>
                    {picked && (
                      <Button
                        variant="outline"
                        onClick={() => setPicked(undefined)}
                      >
                        Clear selection
                      </Button>
                    )}
                  </div>
                  <div className="toolbar">
                    <div>
                      {view !== "IP map" &&
                        dimensions.map((item, index) => (
                          <Button
                            key={item}
                            variant={index === group ? "secondary" : "ghost"}
                            onClick={() => {
                              setGroup(index)
                              setSearch("")
                            }}
                          >
                            {item}
                          </Button>
                        ))}
                    </div>
                    <input
                      aria-label="Filter traffic"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Filter traffic"
                    />
                  </div>
                  <div className="card table">
                    <table>
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Received</th>
                          <th>Sent</th>
                        </tr>
                      </thead>
                      <tbody>
                        {usage
                          .filter((row) =>
                            matches(
                              view === "IP map" || group === 4
                                ? nation(row.label)
                                : row.label
                            )
                          )
                          .slice(0, view === "Timeline" ? 8 : 150)
                          .map((row, index) => (
                            <tr key={index}>
                              <td>
                                {row.path ? (
                                  <button
                                    className="textButton"
                                    title={row.path}
                                    onClick={() => {
                                      setManualPath(row.path!)
                                      changePage("Firewall")
                                    }}
                                  >
                                    {row.label}
                                  </button>
                                ) : view === "IP map" || group === 4 ? (
                                  nation(row.label)
                                ) : (
                                  row.label
                                )}
                              </td>
                              <td>{amount(row.rx)}</td>
                              <td>{amount(row.tx)}</td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                    {!usage.length && (
                      <p className="empty">
                        No matching packet data in this window.
                      </p>
                    )}
                  </div>
                </>
              )}
              {page === "Firewall" && (
                <>
                  <h1>Firewall</h1>
                  <div className="toolbar">
                    <div>
                      {["Processes", "Rule sets", "Connection modes"].map(
                        (item) => (
                          <Button
                            key={item}
                            variant={
                              item === firewallTab ? "secondary" : "ghost"
                            }
                            onClick={() => setFirewallTab(item)}
                          >
                            {item}
                          </Button>
                        )
                      )}
                    </div>
                  </div>
                  <div className="toolbar">
                    <div>
                      {[
                        [1, "Domain"],
                        [2, "Private"],
                        [4, "Public"],
                      ].map(([bit, label]) => (
                        <label key={label}>
                          <input
                            type="checkbox"
                            checked={!!(profileBits & Number(bit))}
                            onChange={() =>
                              setProfileBits(profileBits ^ Number(bit))
                            }
                          />{" "}
                          {label}
                        </label>
                      ))}
                    </div>
                    <small>Windows firewall changes require elevation.</small>
                  </div>
                  {firewallTab === "Processes" && (
                    <>
                      <section className="card controls">
                        <label htmlFor="manual">Executable path</label>
                        <div className="inline">
                          <input
                            id="manual"
                            value={manualPath}
                            onChange={(e) => setManualPath(e.target.value)}
                            placeholder="C:\Path\Application.exe"
                          />
                          <Button
                            disabled={
                              !manualPath || !profileBits || firewallBusy
                            }
                            onClick={() =>
                              void firewallChange(true, manualPath)
                            }
                          >
                            Block
                          </Button>
                          <Button
                            variant="outline"
                            disabled={
                              !manualPath || !profileBits || firewallBusy
                            }
                            onClick={() =>
                              void firewallChange(false, manualPath)
                            }
                          >
                            Remove block
                          </Button>
                        </div>
                      </section>
                      <div className="toolbar">
                        <input
                          placeholder="Search name, PID or path"
                          aria-label="Search running processes"
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                        />
                        <small>
                          Right-click a process for firewall actions.
                        </small>
                      </div>
                    </>
                  )}
                  {firewallTab === "Rule sets" && (
                    <section className="card controls">
                      <h2>Saved firewall profiles</h2>
                      <input
                        placeholder="Profile name"
                        aria-label="Profile name"
                        value={profileName}
                        onChange={(e) => setProfileName(e.target.value)}
                      />
                      <textarea
                        placeholder="One full executable path per line"
                        aria-label="Executable paths"
                        value={paths}
                        onChange={(e) => setPaths(e.target.value)}
                      />
                      <Button
                        disabled={
                          !profileName || !paths || !profileBits || firewallBusy
                        }
                        onClick={() => void profile("save")}
                      >
                        Save profile
                      </Button>
                      {profiles.map((p) => (
                        <div className="toolbar saved" key={p.id}>
                          <span>
                            <strong>{p.name}</strong> · {p.apps.length}{" "}
                            executables
                          </span>
                          <div>
                            {["apply", "remove", "delete"].map((action) => (
                              <Button
                                key={action}
                                variant="outline"
                                disabled={firewallBusy}
                                onClick={() => {
                                  if (
                                    action !== "delete" ||
                                    confirm(
                                      `Remove the rules and delete ${p.name}?`
                                    )
                                  )
                                    void profile(action, p.id)
                                }}
                              >
                                {action === "delete"
                                  ? "Remove rules and delete"
                                  : action === "apply"
                                    ? "Apply"
                                    : "Remove rules"}
                              </Button>
                            ))}
                          </div>
                        </div>
                      ))}
                    </section>
                  )}
                  {firewallTab === "Connection modes" && (
                    <>
                      <section className="card controls">
                        <h2>Lockdown</h2>
                        <p>
                          Block traffic on the selected Windows firewall
                          profiles.
                        </p>
                        <div className="inline">
                          <Button
                            variant="destructive"
                            disabled={!profileBits || firewallBusy}
                            onClick={() => {
                              if (
                                confirm(
                                  "Enable Lockdown? This can interrupt connectivity."
                                )
                              )
                                void firewallChange(true)
                            }}
                          >
                            Enable Lockdown
                          </Button>
                          <Button
                            variant="outline"
                            disabled={!profileBits || firewallBusy}
                            onClick={() => void firewallChange(false)}
                          >
                            Remove Lockdown
                          </Button>
                        </div>
                      </section>
                      <section className="card controls">
                        <h2>Ask to Connect</h2>
                        <p>
                          Require approval for new outbound connections while
                          deadWall is open.
                        </p>
                        <Button
                          variant="outline"
                          onClick={() => {
                            if (
                              requests.active ||
                              confirm(
                                "Start outbound approval mode? This can interrupt network access."
                              )
                            )
                              void approval(requests.active ? "stop" : "start")
                          }}
                        >
                          {requests.active ? "Stop asking" : "Start asking"}
                        </Button>
                        {requests.requests.map((path, index) => (
                          <div className="toolbar saved" key={path}>
                            <span>{path}</span>
                            <div>
                              <Button
                                variant="outline"
                                onClick={() => void approval("allow", index)}
                              >
                                Allow for session
                              </Button>
                              <Button
                                variant="outline"
                                onClick={() => void approval("deny", index)}
                              >
                                Keep blocked
                              </Button>
                            </div>
                          </div>
                        ))}
                      </section>
                    </>
                  )}
                </>
              )}
              {page === "Hardware" && (
                <>
                  <h1>Hardware resources</h1>
                  <div className="totals card">
                    {[
                      ["CPU", `${resources.cpu.toFixed(1)}%`],
                      [
                        "RAM",
                        resources.capacity
                          ? `${amount(resources.memory)} / ${amount(resources.capacity)}`
                          : "Collecting",
                      ],
                      [
                        "GPU",
                        resources.gpu == null
                          ? "Unavailable"
                          : `${resources.gpu.toFixed(1)}%`,
                      ],
                    ].map(([label, value], index) => (
                      <div key={label}>
                        <small>{label}</small>
                        <strong>{value}</strong>
                        <div className="spark" aria-hidden="true">
                          {resourceHistory.map((r, i) => {
                            const percent =
                              index === 0
                                ? r.cpu
                                : index === 1
                                  ? r.capacity
                                    ? (r.memory / r.capacity) * 100
                                    : 0
                                  : (r.gpu ?? 0)
                            return (
                              <i
                                key={i}
                                style={{
                                  height: `${Math.max(3, Math.min(100, percent))}%`,
                                }}
                              />
                            )
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="toolbar">
                    <h2>Running processes</h2>
                    <input
                      placeholder="Filter processes"
                      aria-label="Filter processes"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </div>
                </>
              )}
              {(page === "Hardware" ||
                (page === "Firewall" && firewallTab === "Processes")) && (
                <div className="card table">
                  <table>
                    <thead>
                      <tr>
                        <th>Application</th>
                        <th>PID</th>
                        {page === "Firewall" ? (
                          <th>Executable path</th>
                        ) : (
                          <>
                            <th>CPU</th>
                            <th>RAM</th>
                            <th>Disk I/O</th>
                            <th>GPU</th>
                          </>
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      {processRows.map((p) => (
                        <tr
                          key={p.pid}
                          onContextMenu={(e) => {
                            e.preventDefault()
                            setMenu({
                              x: Math.min(e.clientX, window.innerWidth - 266),
                              y: Math.min(e.clientY, window.innerHeight - 175),
                              process: p,
                            })
                          }}
                        >
                          <td>
                            <button
                              className="textButton"
                              onClick={() => {
                                if (p.path) {
                                  setManualPath(p.path)
                                  changePage("Firewall")
                                  setFirewallTab("Processes")
                                }
                              }}
                            >
                              {p.name}
                            </button>
                          </td>
                          <td>{p.pid}</td>
                          {page === "Firewall" ? (
                            <td title={p.path}>{p.path || "Unavailable"}</td>
                          ) : (
                            <>
                              <td>{p.cpu.toFixed(1)}%</td>
                              <td>{amount(p.memory)}</td>
                              <td>{amount(p.disk)}</td>
                              <td>
                                {p.gpu == null ? "—" : `${p.gpu.toFixed(1)}%`}
                              </td>
                            </>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!processRows.length && (
                    <p className="empty">No matching running processes.</p>
                  )}
                </div>
              )}
              {page === "Alerts" && (
                <>
                  <h1>Security alerts</h1>
                  {alerts.length ? (
                    alerts.map((a, index) => (
                      <section key={index} className="card controls alert">
                        <div>
                          <strong>{a.title}</strong>
                          <small>{new Date(a.time).toLocaleString()}</small>
                        </div>
                        <p>{a.detail}</p>
                      </section>
                    ))
                  ) : (
                    <p>No alerts recorded.</p>
                  )}
                </>
              )}
              {page === "Things" && (
                <>
                  <div className="toolbar">
                    <h1>Network devices</h1>
                    <div>
                      <select
                        aria-label="Local IPv4 source"
                        value={scanSource}
                        onChange={(e) => setScanSource(e.target.value)}
                      >
                        <option value="">Select local address</option>
                        {scanSources.map((address) => (
                          <option key={address}>{address}</option>
                        ))}
                      </select>
                      <Button
                        disabled={!scanSource || scanning}
                        onClick={() => void discover()}
                      >
                        {scanning ? "Scanning…" : "Scan subnet"}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => void send("devices")}
                      >
                        Refresh
                      </Button>
                    </div>
                  </div>
                  <div className="card table">
                    <table>
                      <thead>
                        <tr>
                          <th>IP address</th>
                          <th>MAC address</th>
                          <th>Interface</th>
                        </tr>
                      </thead>
                      <tbody>
                        {devices.map((d) => (
                          <tr key={d.address + d.interface}>
                            <td>{d.address}</td>
                            <td>{d.mac}</td>
                            <td>{d.interface}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {!devices.length && (
                      <p className="empty">No LAN neighbors found.</p>
                    )}
                  </div>
                </>
              )}
              {page === "Settings" && (
                <>
                  <h1>Settings</h1>
                  <section className="card controls">
                    <h2>Appearance</h2>
                    <div
                      className="paletteOptions"
                      role="group"
                      aria-label="Color palette"
                    >
                      {paletteIds.map((id) => {
                        const item = palettes[id]
                        return (
                          <Button
                            key={id}
                            className="paletteChoice"
                            variant={palette === id ? "secondary" : "outline"}
                            aria-pressed={palette === id}
                            title={`Light: ${item.light[0]} · Dark: ${item.dark[0]}`}
                            onClick={() => choosePalette(id)}
                          >
                            <span
                              className="paletteSwatches"
                              aria-hidden="true"
                            >
                              {[item.light, item.dark].map(
                                ([
                                  label,
                                  [base, surface, , , receive, send],
                                ]) => (
                                  <i
                                    key={label}
                                    style={{
                                      background: `linear-gradient(145deg, ${base} 25%, ${surface} 55%, ${receive} 80%, ${send})`,
                                    }}
                                  />
                                )
                              )}
                            </span>
                            {item.name}
                          </Button>
                        )
                      })}
                    </div>
                    <small>
                      The sun and moon button switches between this palette’s
                      light and dark variants.
                    </small>
                  </section>
                  <section className="card controls">
                    <h2>Capture and display</h2>
                    <label>
                      <input
                        type="checkbox"
                        checked={trayEnabled}
                        disabled={trayPending}
                        onChange={(event) =>
                          void changeTray(event.target.checked)
                        }
                      />{" "}
                      Minimize to tray
                    </label>
                    {trayEnabled && (
                      <small>
                        Use the deadWall tray icon to reopen the window or quit.
                      </small>
                    )}
                    <label htmlFor="source">Capture source</label>
                    <div className="inline">
                      <select
                        id="source"
                        value={source}
                        onChange={(e) =>
                          void send("source", { key: e.target.value })
                        }
                      >
                        <option value="">Select source</option>
                        {sources.map((s) => (
                          <option key={s.key} value={s.key}>
                            {s.name} · {s.kind}
                          </option>
                        ))}
                      </select>
                      <Button
                        variant="outline"
                        onClick={() => void send("sources")}
                      >
                        Refresh adapters
                      </Button>
                    </div>
                    <label>
                      <input
                        type="checkbox"
                        checked={grid}
                        onChange={(e) => setGrid(e.target.checked)}
                      />{" "}
                      Timeline guide lines
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={inspector}
                        onChange={(e) => setInspector(e.target.checked)}
                      />{" "}
                      Show system inspector
                    </label>
                    <label>
                      Live map activity window{" "}
                      <select
                        value={mapSeconds}
                        onChange={(e) => setMapSeconds(Number(e.target.value))}
                      >
                        {[15, 30, 60, 120].map((s) => (
                          <option key={s} value={s}>
                            {s} seconds
                          </option>
                        ))}
                      </select>
                    </label>
                  </section>
                  <section className="card controls">
                    <h2>Geographic filtering</h2>
                    <p>
                      Block matching remote addresses across all apps while
                      deadWall is open. Applying rules requires elevation.
                    </p>
                    <div className="wrap inline">
                      {continents.map(([code, label]) => (
                        <Button
                          key={code}
                          variant={
                            spec.continents.includes(code)
                              ? "secondary"
                              : "outline"
                          }
                          aria-pressed={spec.continents.includes(code)}
                          onClick={() =>
                            setSpec({
                              ...spec,
                              continents: spec.continents.includes(code)
                                ? spec.continents.filter((c) => c !== code)
                                : [...spec.continents, code],
                            })
                          }
                        >
                          {label}
                        </Button>
                      ))}
                    </div>
                    <label>
                      Countries{" "}
                      <input
                        value={spec.countries}
                        placeholder="ISO codes, separated by commas"
                        onChange={(e) =>
                          setSpec({ ...spec, countries: e.target.value })
                        }
                      />
                    </label>
                    <label>
                      IP ranges{" "}
                      <textarea
                        value={spec.cidrs}
                        placeholder="One IPv4 or IPv6 CIDR per line"
                        onChange={(e) =>
                          setSpec({ ...spec, cidrs: e.target.value })
                        }
                      />
                    </label>
                    <div className="inline">
                      <Button
                        disabled={filterPending}
                        onClick={() => void applyGeo(spec)}
                      >
                        Apply filters
                      </Button>
                      <Button
                        variant="outline"
                        disabled={filterPending || !filters}
                        onClick={() => void applyGeo(emptySpec)}
                      >
                        Turn off
                      </Button>
                      <small>
                        {filterPending
                          ? "Applying…"
                          : filters
                            ? `Active · ${filters} ranges`
                            : "Off"}
                      </small>
                    </div>
                  </section>
                  <section className="card controls">
                    <h2>Local history</h2>
                    <code>{storage || status}</code>
                  </section>
                </>
              )}
            </main>
            {inspector && (
              <aside className="inspector card">
                <h2>System activity</h2>
                <dl>
                  <dt>CPU</dt>
                  <dd>{resources.cpu.toFixed(1)}%</dd>
                  <dt>RAM</dt>
                  <dd>
                    {amount(resources.memory)} / {amount(resources.capacity)}
                  </dd>
                  <dt>GPU</dt>
                  <dd>
                    {resources.gpu == null
                      ? "Unavailable"
                      : `${resources.gpu.toFixed(1)}%`}
                  </dd>
                  <dt>Disk I/O</dt>
                  <dd>
                    {resources.disk == null
                      ? "Unavailable"
                      : amount(resources.disk) + "/s"}
                  </dd>
                </dl>
              </aside>
            )}
          </div>
        </div>
      </div>
      <footer className="appFooter">
        <span className="footerBrand">
          <span className="footerMark" aria-hidden="true" />
          Copywrong 2026 <span aria-hidden="true">·</span>{" "}
          <a
            href="https://digitalchaos.dev/"
            onClick={(event) => {
              event.preventDefault()
              void invoke("open_publisher_site").catch(fail)
            }}
          >
            digitalchaos.dev
          </a>
        </span>
        <span className="footerStatus" title={status}>
          {status}
        </span>
      </footer>
      {menu && (
        <div
          className="context card"
          role="menu"
          style={{ left: menu.x, top: menu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <strong>{menu.process.name}</strong>
          <small>PID {menu.process.pid}</small>
          <Button
            role="menuitem"
            variant="ghost"
            disabled={!menu.process.path || !profileBits || firewallBusy}
            onClick={() => void firewallChange(true, menu.process.path)}
          >
            Block inbound and outbound
          </Button>
          <Button
            role="menuitem"
            variant="ghost"
            disabled={!menu.process.path || !profileBits || firewallBusy}
            onClick={() => void firewallChange(false, menu.process.path)}
          >
            Remove application block
          </Button>
          <Button
            role="menuitem"
            variant="ghost"
            disabled={!menu.process.path}
            onClick={() => {
              void navigator.clipboard.writeText(menu.process.path!).catch(fail)
              setMenu(undefined)
            }}
          >
            Copy executable path
          </Button>
        </div>
      )}
    </div>
  )
}

export default function App() {
  return new URLSearchParams(location.search).has("mini") ? (
    <Mini />
  ) : (
    <Dashboard />
  )
}
