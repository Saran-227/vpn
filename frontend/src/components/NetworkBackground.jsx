// Purely decorative — pointer-events: none, aria-hidden
// Nodes are fixed percentage positions; CSS keyframes handle drift.
// No JS animation loop, no canvas, no library.

const NODES = [
  { id: 'n0', cx: '8%',  cy: '18%', d: 'drift-a' },
  { id: 'n1', cx: '28%', cy: '9%',  d: 'drift-b' },
  { id: 'n2', cx: '52%', cy: '14%', d: 'drift-c' },
  { id: 'n3', cx: '74%', cy: '8%',  d: 'drift-a' },
  { id: 'n4', cx: '91%', cy: '22%', d: 'drift-b' },
  { id: 'n5', cx: '6%',  cy: '52%', d: 'drift-c' },
  { id: 'n6', cx: '35%', cy: '44%', d: 'drift-b' },
  { id: 'n7', cx: '62%', cy: '38%', d: 'drift-a' },
  { id: 'n8', cx: '88%', cy: '55%', d: 'drift-c' },
  { id: 'n9', cx: '18%', cy: '78%', d: 'drift-a' },
  { id: 'n10', cx: '46%', cy: '72%', d: 'drift-b' },
  { id: 'n11', cx: '78%', cy: '80%', d: 'drift-c' },
]

// Edges between node index pairs
const EDGES = [
  [0,1],[1,2],[2,3],[3,4],
  [0,5],[1,6],[2,6],[3,7],[4,8],
  [5,6],[6,7],[7,8],
  [5,9],[6,10],[7,10],[8,11],
  [9,10],[10,11],
]

export default function NetworkBackground() {
  return (
    <svg
      className="net-bg"
      aria-hidden="true"
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 100 100"
      preserveAspectRatio="xMidYMid slice"
    >
      <defs>
        <filter id="nb-blur">
          <feGaussianBlur stdDeviation="0.4" />
        </filter>
      </defs>

      {/* edges */}
      {EDGES.map(([a, b]) => {
        const na = NODES[a], nb = NODES[b]
        return (
          <line
            key={`${a}-${b}`}
            x1={na.cx} y1={na.cy}
            x2={nb.cx} y2={nb.cy}
            stroke="rgba(147,197,253,0.55)"
            strokeWidth="0.18"
            strokeOpacity="0.22"
            filter="url(#nb-blur)"
          />
        )
      })}

      {/* nodes */}
      {NODES.map(n => (
        <circle
          key={n.id}
          cx={n.cx} cy={n.cy}
          r="0.55"
          fill="rgba(147,197,253,0.35)"
          fillOpacity="0.55"
          className={`nb-node nb-${n.d}`}
          filter="url(#nb-blur)"
        />
      ))}
    </svg>
  )
}
