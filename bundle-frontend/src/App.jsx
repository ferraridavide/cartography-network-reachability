import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import * as d3 from "d3";
import GUI from "lil-gui";

const DATA_URL = import.meta.env.VITE_BUNDLE_DATA_URL || "/packet_paths_bundle.json";
const EXPORT_SIZE = 4000;
const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const EXPORT_SVG_STYLES = `
  text {
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  .zoom-hitbox {
    display: none;
  }
  .node-dot {
    stroke: #ffffff;
    stroke-width: 1.2px;
  }
  .node-dot.isolated {
    opacity: 0.55;
  }
  .node-dot.selected {
    stroke: #22c55e;
    stroke-width: 2px;
  }
  .node-dot.dimmed {
    opacity: 0.12;
  }
  .node-label {
    cursor: pointer;
    fill: #111827;
    font-size: 10px;
  }
  .node-label.selected {
    fill: #22c55e;
    font-weight: 700;
  }
  .node-label.destination {
    fill: #38bdf8;
    font-weight: 700;
  }
  .node-label.dimmed {
    opacity: 0.16;
  }
  .link {
    fill: none;
    stroke: #64748b;
    stroke-opacity: 0.34;
    mix-blend-mode: multiply;
  }
  .link.wildcard {
    stroke: #ef4444;
  }
  .link.broad {
    stroke: #f59e0b;
  }
  .link.selected {
    stroke: #22c55e;
    stroke-opacity: 0.9;
    mix-blend-mode: normal;
  }
  .link.dimmed {
    stroke-opacity: 0.04;
  }
  .ray-tree-link {
    fill: none;
    stroke-opacity: 0.72;
    stroke-width: 1.8px;
    stroke-linecap: round;
    stroke-linejoin: round;
    pointer-events: stroke;
  }
  .ray-tree-link.selected {
    stroke: #22c55e;
    stroke-opacity: 1;
    stroke-width: 2.8px;
  }
  .ray-tree-node circle {
    stroke: #ffffff;
    stroke-width: 1.6px;
  }
  .ray-tree-node.selected circle {
    stroke: #22c55e;
    stroke-width: 2.4px;
  }
  .ray-tree-label {
    fill: #000000;
    font-size: 9px;
    opacity: 0.82;
    paint-order: stroke;
    stroke: #ffffff;
    stroke-width: 3px;
    stroke-linejoin: round;
  }
`;

function readRoute() {
  const match = window.location.pathname.match(/^\/rays\/(outbound|inbound)\/(.+)$/);
  if (match) {
    return {
      page: "rays",
      direction: match[1],
      nodeId: decodeURIComponent(match[2]),
    };
  }
  const params = new URLSearchParams(window.location.search);
  return {
    page: "bundle",
    nodeId: params.get("node") || null,
  };
}

function pushRoute(path) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new Event("popstate"));
}

function bundlePath(nodeId) {
  return nodeId ? `/?node=${encodeURIComponent(nodeId)}` : "/";
}

function raysPath(direction, nodeId) {
  return `/rays/${direction}/${encodeURIComponent(nodeId)}`;
}

function stringify(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function summarizeRule(rule) {
  return [
    rule.sg_id,
    rule.protocol,
    rule.from_port === null || rule.from_port === undefined
      ? "*"
      : `${rule.from_port}-${rule.to_port}`,
    (rule.cidrs || []).join(", "),
  ]
    .filter(Boolean)
    .join(" | ");
}

function summarizeRoute(route) {
  return [route.route_table_id, route.destination, `${route.target_kind}:${route.target}`]
    .filter(Boolean)
    .join(" | ");
}

function effectiveResourceType(node) {
  if (!node) return "Unknown";
  const resourceType = node.resource_type || "Unknown";
  if (resourceType !== "NetworkInterface") return resourceType;

  const properties = node.properties || {};
  const description = String(properties.description || node.label || "").toLowerCase();
  const interfaceType = String(properties.interface_type || "").toLowerCase();
  const requester = String(properties.requester_id || "").toLowerCase();

  if (description.startsWith("elb ") || requester === "amazon-elb") return "LoadBalancer";
  if (interfaceType === "lambda" || description.startsWith("aws lambda vpc eni")) {
    return "LambdaFunction";
  }
  if (interfaceType === "vpc_endpoint" || description.startsWith("vpc endpoint")) {
    return "VPCEndpoint";
  }
  if (interfaceType === "transit_gateway" || description.includes("transit gateway")) {
    return "TransitGatewayAttachment";
  }
  if (interfaceType === "nat_gateway" || description.includes("nat gateway")) {
    return "NATGateway";
  }
  if (requester === "amazon-elasticache" || description.startsWith("elasticache")) {
    return "ElastiCache";
  }
  if (description === "rdsnetworkinterface" || description.startsWith("rds")) {
    return "RDSInstance";
  }
  return resourceType;
}

function nodeAccountId(node) {
  return node?.account_id || node?.properties?.account_id || "unknown-account";
}

function nodeAccountName(node) {
  return node?.account_name || node?.properties?.account_name || null;
}

function accountSeparatorLabel(accountId, accountNodes) {
  const accountNames = uniqueValues(accountNodes.map(nodeAccountName));
  const accountName = accountNames.length === 1 ? accountNames[0] : null;
  return accountName && accountName !== accountId ? `${accountName} (${accountId})` : accountId;
}

function buildVisibleHierarchy(nodes) {
  const nodeAccount = (node) => nodeAccountId(node);
  const nodeRegion = (node) => node.properties?.region || "unknown-region";
  const nodeVpc = (node) => node.vpc_id || node.properties?.vpc_id || "unknown-vpc";
  const nodeType = (node) => effectiveResourceType(node);
  const leafFor = (node) => ({
    name: conciseNodeLabel(node) || node.label || node.eni_id,
    sort_key: `${node.private_ip || ""}|${node.eni_id}`,
    node_id: node.id,
    label: conciseNodeLabel(node) || node.label,
    eni_label: node.eni_label,
    private_ip: node.private_ip,
    resource_type: effectiveResourceType(node),
  });
  const groupFor = ([groupId, groupNodes]) => ({
    name: groupNodes[0]?.group_label || groupId,
    sort_key: groupNodes[0]?.group_label || groupId,
    group_id: groupId,
    children: groupNodes
      .slice()
      .sort(
        (a, b) =>
          d3.ascending(a.private_ip, b.private_ip) ||
          d3.ascending(a.eni_id, b.eni_id),
      )
      .map(leafFor),
  });
  const sortedGroups = (items, keyFn) =>
    d3
      .groups(items, keyFn)
      .sort(([a], [b]) => d3.ascending(a, b));

  const children = sortedGroups(nodes, nodeAccount).map(([account, accountNodes]) => {
    const accountLabel = accountSeparatorLabel(account, accountNodes);
    const spacerBefore = {
      name: "",
      sort_key: "",
      node_id: `account-spacer-before:${account}`,
      is_account_spacer: true,
    };
    const accountSeparator = {
      name: accountLabel,
      sort_key: " ",
      node_id: `account-separator:${account}`,
      is_account_separator: true,
      label: accountLabel,
      account_id: account,
    };
    return {
      name: account,
      sort_key: account,
      children: [
        spacerBefore,
        accountSeparator,
        ...sortedGroups(accountNodes, nodeRegion).map(([region, regionNodes]) => ({
          name: region,
          sort_key: region,
          children: sortedGroups(regionNodes, nodeVpc).map(([vpc, vpcNodes]) => ({
            name: vpc,
            sort_key: vpc,
            children: sortedGroups(vpcNodes, nodeType).map(([resourceType, typeNodes]) => ({
              name: resourceType,
              sort_key: resourceType,
              children: sortedGroups(typeNodes, (node) => node.group_id).map(groupFor),
            })),
          })),
        })),
      ],
    };
  });
  return { name: "aws", children };
}

function keyValueRows(values) {
  return (
    <table className="kv">
      <tbody>
        {Object.entries(values).map(([key, value]) => (
          <tr key={key}>
            <th>{key}</th>
            <td>{stringify(value)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function loadImage(src) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = reject;
    image.src = src;
  });
}

function canvasToPngBlob(canvas) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) {
        resolve(blob);
      } else {
        reject(new Error("Unable to render chart PNG."));
      }
    }, "image/png");
  });
}

function prepareSvgExport(svgElement, size = EXPORT_SIZE) {
  const viewBox = svgElement?.getAttribute("viewBox");
  if (!svgElement || !viewBox) return null;

  const [x, y, width, height] = viewBox.split(/\s+/).map(Number);
  const clone = svgElement.cloneNode(true);
  clone.setAttribute("xmlns", SVG_NAMESPACE);
  clone.setAttribute("width", String(size));
  clone.setAttribute("height", String(size));
  clone.setAttribute("viewBox", viewBox);
  clone.setAttribute("preserveAspectRatio", "xMidYMid meet");
  clone.removeAttribute("style");

  const style = document.createElementNS(SVG_NAMESPACE, "style");
  style.textContent = EXPORT_SVG_STYLES;
  clone.insertBefore(style, clone.firstChild);

  const background = document.createElementNS(SVG_NAMESPACE, "rect");
  background.setAttribute("x", String(x));
  background.setAttribute("y", String(y));
  background.setAttribute("width", String(width));
  background.setAttribute("height", String(height));
  background.setAttribute("fill", "#ffffff");
  clone.insertBefore(background, style.nextSibling);

  return clone;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportSvg(svgElement, filename, size = EXPORT_SIZE) {
  const clone = prepareSvgExport(svgElement, size);
  if (!clone) return;
  const svgText = new XMLSerializer().serializeToString(clone);
  const svgBlob = new Blob([svgText], { type: "image/svg+xml;charset=utf-8" });
  downloadBlob(svgBlob, filename);
}

async function exportSvgAsPng(svgElement, filename, size = EXPORT_SIZE) {
  const clone = prepareSvgExport(svgElement, size);
  if (!clone) return;

  const svgText = new XMLSerializer().serializeToString(clone);
  const svgBlob = new Blob([svgText], { type: "image/svg+xml;charset=utf-8" });
  const svgUrl = URL.createObjectURL(svgBlob);
  try {
    const image = await loadImage(svgUrl);
    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    const context = canvas.getContext("2d");
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, size, size);
    context.drawImage(image, 0, 0, size, size);

    const pngBlob = await canvasToPngBlob(canvas);
    downloadBlob(pngBlob, filename);
  } catch (error) {
    console.error(error);
    window.alert("Unable to export chart PNG.");
  } finally {
    URL.revokeObjectURL(svgUrl);
  }
}

function Ray({ path }) {
  return (
    <div className="ray">
      <div>
        <b>packet</b> {stringify(path.packet_space)}
      </div>
      {path.elb_target ? (
        <div>
          <b>target group</b> {stringify(path.elb_target)}
        </div>
      ) : null}
      {path.tgw_hop ? (
        <div>
          <b>tgw hop</b> {stringify(path.tgw_hop)}
        </div>
      ) : null}
      <div>
        <b>egress</b> {summarizeRule(path.egress_rule)}
      </div>
      <div>
        <b>route</b> {summarizeRoute(path.route)}
      </div>
      <div>
        <b>ingress</b> {summarizeRule(path.ingress_rule)}
      </div>
    </div>
  );
}

function Details({ node, outgoing, incoming, nodesById, onShowOutbound, onShowInbound }) {
  if (!node) {
    return (
      <section id="details">
        <h1>Hierarchical Edge Bundling</h1>
        <p className="muted">
          Each label is an ENI. Curves represent at least one packet-space path
          from a source ENI to a destination ENI.
        </p>
      </section>
    );
  }

  const isGroupedElb = Boolean(node.grouped_eni_ids?.length);

  return (
    <section id="details">
      <h1>{conciseNodeLabel(node)}</h1>
      <div className="pillrow">
        <span className="pill">{effectiveResourceType(node)}</span>
        <span className="pill">{node.group_label}</span>
        <span className="pill">{outgoing.length} outbound</span>
        <span className="pill">{incoming.length} inbound</span>
      </div>
      <div className="detail-actions">
        <button type="button" onClick={onShowOutbound} disabled={isGroupedElb || !outgoing.length}>
          Show node outbound rays
        </button>
        <button type="button" onClick={onShowInbound} disabled={isGroupedElb || !incoming.length}>
          Show node inbound rays
        </button>
      </div>
      <h2>ENI</h2>
      {keyValueRows({
        eni_id: node.eni_id,
        eni: node.eni_label,
        private_ip: node.private_ip,
        vpc_id: node.vpc_id,
        subnet_id: node.subnet_id,
        security_groups: node.security_groups,
        resource_arn: node.resource_arn,
      })}
      <h2>Outbound Rays</h2>
      {outgoing.length ? (
        outgoing.map((edge) => {
          const target = nodesById.get(edge.target);
          return (
            <section className="connection" key={edge.id}>
              <div className="connection-head">
                <span>{conciseNodeLabel(target) || edge.target}</span>
                <span className="muted">
                  {edge.path_count} path{edge.path_count === 1 ? "" : "s"} |{" "}
                  {edge.caption}
                </span>
              </div>
              <div className="connection-body">
                <div className="pillrow">
                  {edge.wildcard ? <span className="pill">wildcard</span> : null}
                  {edge.broad_ingress ? (
                    <span className="pill">broad ingress</span>
                  ) : null}
                  <span className="pill">{target?.group_label || "-"}</span>
                </div>
                {edge.paths.map((path, index) => (
                  <Ray path={path} key={`${edge.id}-${index}`} />
                ))}
              </div>
            </section>
          );
        })
      ) : (
        <p className="muted">No outbound rays were found for this ENI.</p>
      )}
    </section>
  );
}

function routeStepLabel(route) {
  return `${route.route_table_id || "route table"} -> ${route.target_kind || "target"}:${
    route.target || "-"
  }`;
}

function ruleStepLabel(rule) {
  const port =
    rule.from_port === null || rule.from_port === undefined
      ? "*"
      : `${rule.from_port}-${rule.to_port}`;
  return `${rule.sg_id || "security group"} ${rule.protocol || "*"} ${port}`;
}

function makeRayItem(id, name, kind, detail, children = [], edge = null, resourceKey = id) {
  return { id, name, kind, detail, children, edge, resourceKey, rays: [] };
}

function nodeStepLabel(node, fallbackId) {
  return conciseNodeLabel(node) || fallbackId || "ENI";
}

function shortRuleLabel(rule, direction) {
  return `${direction} ${rule.sg_id || "sg"}`;
}

function shortRouteLabel(route) {
  if (route.target_kind === "vpc_peering") {
    return route.target || "pcx";
  }
  return `${route.route_table_id || "rt"} -> ${route.target_kind || "target"}:${
    route.target || "-"
  }`;
}

function tagValue(value, key) {
  if (!value) return null;
  if (Array.isArray(value)) {
    const match = value.find(
      (item) =>
        item &&
        typeof item === "object" &&
        String(item.Key || item.key || "").toLowerCase() === key.toLowerCase(),
    );
    return match ? String(match.Value || match.value || "") : null;
  }
  if (typeof value === "object") {
    return value[key] || value[key.toLowerCase()] || value[key.toUpperCase()] || null;
  }
  return null;
}

function cleanNameTag(value) {
  if (!value) return null;
  const text = String(value).trim();
  if (!text || text.startsWith("vpc-") || text.startsWith("pcx-")) return null;
  if (text.includes(" via pcx-")) return null;
  return text;
}

function peeringLabelFromNode(node) {
  const properties = node?.properties || {};
  const connectionId =
    properties.terminal_connection_id ||
    node?.subnet_id?.replace("external:", "") ||
    node?.eni_id?.match(/pcx-[a-z0-9]+/)?.[0];
  if (properties.terminal_kind !== "vpc_peering" && !connectionId?.startsWith("pcx-")) {
    return null;
  }

  const name = cleanNameTag(
    properties.terminal_connection_name ||
      properties.connection_name ||
      properties.name_tag ||
      properties.Name ||
      tagValue(properties.tags, "Name") ||
      tagValue(properties.Tags, "Name"),
  );
  return name ? `${name} (pcx)` : connectionId || null;
}

function conciseNodeLabel(node) {
  if (!node) return null;
  return peeringLabelFromNode(node) || node.label || node.eni_label || node.id;
}

const RESOURCE_PALETTE = [
  "#2563eb",
  "#06b6d4",
  "#14b8a6",
  "#22c55e",
  "#84cc16",
  "#a3e635",
  "#eab308",
  "#f97316",
  "#fb923c",
  "#ef4444",
  "#f43f5e",
  "#fb7185",
  "#ec4899",
  "#d946ef",
  "#a855f7",
  "#8b5cf6",
  "#6366f1",
  "#4f46e5",
  "#0ea5e9",
  "#10b981",
  "#38bdf8",
  "#34d399",
  "#2dd4bf",
  "#60a5fa",
  "#c084fc",
  "#e879f9",
];

const ACCOUNT_PALETTE = [
  "#2563eb",
  "#f97316",
  "#22c55e",
  "#d946ef",
  "#06b6d4",
  "#ef4444",
  "#8b5cf6",
  "#84cc16",
  "#ec4899",
  "#14b8a6",
  "#eab308",
  "#6366f1",
];

function hashString(value) {
  return Array.from(String(value || "Unknown")).reduce(
    (hash, char) => (hash * 31 + char.charCodeAt(0)) >>> 0,
    0,
  );
}

function resourceColor(resourceType) {
  return RESOURCE_PALETTE[hashString(resourceType) % RESOURCE_PALETTE.length];
}

function isGroupableResourceNode(node) {
  return node?.group_id?.startsWith("group:");
}

function groupedResourceNodeId(groupId) {
  return `grouped-resource:${groupId}`;
}

function uniqueValues(values) {
  return [...new Set(values.filter((value) => value !== null && value !== undefined && value !== ""))];
}

function joinOrMixed(values) {
  const unique = uniqueValues(values);
  if (!unique.length) return null;
  return unique.length === 1 ? unique[0] : "multiple";
}

function cleanGroupedMemberLabel(label) {
  return String(label || "")
    .replace(/\s+\([a-z]{2}-[a-z]+-\d[a-z]\)$/i, "")
    .trim();
}

function groupedResourceLabel(groupId, members) {
  const memberLabels = uniqueValues(
    members.map((node) => cleanGroupedMemberLabel(conciseNodeLabel(node))),
  );
  if (memberLabels.length === 1) return memberLabels[0];

  const groupLabels = uniqueValues(
    members.map((node) => cleanGroupedMemberLabel(node.group_label)),
  );
  if (groupLabels.length === 1) {
    const elbMatch = groupLabels[0].match(/^ELB\s+(?:app|net|gwy)\/([^/]+)/);
    if (elbMatch) return elbMatch[1];
    return groupLabels[0].replace(/\s+\w+\s+\(\d+\s+ENIs\)$/i, "");
  }

  return groupId;
}

function buildGroupedResourceNode(groupId, members) {
  const first = members[0];
  const label = groupedResourceLabel(groupId, members);
  const securityGroups = uniqueValues(members.flatMap((node) => node.security_groups || []));
  return {
    ...first,
    id: groupedResourceNodeId(groupId),
    eni_id: `${members.length} ENIs`,
    eni_label: members.map((node) => node.eni_label || node.eni_id).join(", "),
    label,
    private_ip: `${members.length} ENIs`,
    resource_type: effectiveResourceType(first),
    vpc_id: joinOrMixed(members.map((node) => node.vpc_id)),
    subnet_id: joinOrMixed(members.map((node) => node.subnet_id)),
    security_groups: securityGroups,
    grouped_eni_ids: members.map((node) => node.id),
    properties: {
      ...(first.properties || {}),
      grouped: true,
      grouped_eni_ids: members.map((node) => node.id),
      member_eni_ids: members.map((node) => node.eni_id),
      member_count: members.length,
    },
  };
}

function mergeEdges(edges) {
  return edges.map(([id, group]) => {
    const first = group[0];
    const packetLabels = uniqueValues(group.flatMap((edge) => edge.packet_labels || []));
    const packetSpaces = uniqueValues(group.flatMap((edge) => edge.packet_spaces || []));
    const protocols = uniqueValues(group.flatMap((edge) => edge.protocols || []));
    const ports = uniqueValues(group.flatMap((edge) => edge.ports || []));
    const dstCidrs = uniqueValues(group.flatMap((edge) => edge.dst_cidrs || []));
    const routeIds = uniqueValues(group.flatMap((edge) => edge.route_ids || []));
    const routeTargets = uniqueValues(group.flatMap((edge) => edge.route_targets || []));
    const egressRules = uniqueValues(group.flatMap((edge) => edge.egress_rules || []));
    const ingressRules = uniqueValues(group.flatMap((edge) => edge.ingress_rules || []));
    const elbTargetGroups = uniqueValues(group.flatMap((edge) => edge.elb_target_groups || []));
    const paths = group.flatMap((edge) => edge.paths || []);
    const pathCount = d3.sum(group, (edge) => edge.path_count || edge.paths?.length || 0);
    return {
      ...first,
      id,
      path_count: pathCount,
      width: Math.min(7, d3.sum(group, (edge) => edge.width || 1)),
      caption: packetLabels.length ? packetLabels.join(", ") : first.caption,
      label: packetLabels.length ? packetLabels.join(", ") : first.label,
      packet_labels: packetLabels,
      packet_spaces: packetSpaces,
      protocols,
      ports,
      dst_cidrs: dstCidrs,
      route_ids: routeIds,
      route_targets: routeTargets,
      egress_rules: egressRules,
      ingress_rules: ingressRules,
      elb_target_groups: elbTargetGroups,
      paths,
      wildcard: group.some((edge) => edge.wildcard),
      broad_ingress: group.some((edge) => edge.broad_ingress),
      grouped_edge_ids: group.map((edge) => edge.id),
    };
  });
}

function buildBundleViewData(data, groupMultiEniResources) {
  if (!groupMultiEniResources) return data;

  const resourceGroups = d3.group(
    data.nodes.filter((node) => isGroupableResourceNode(node)),
    (node) => node.group_id,
  );
  const collapsedGroups = new Map(
    [...resourceGroups].filter(([, nodes]) => nodes.length > 1),
  );
  if (!collapsedGroups.size) return data;

  const nodeIdMap = new Map();
  for (const [groupId, nodes] of collapsedGroups) {
    const groupedId = groupedResourceNodeId(groupId);
    nodes.forEach((node) => nodeIdMap.set(node.id, groupedId));
  }

  const groupedNodes = [...collapsedGroups].map(([groupId, nodes]) =>
    buildGroupedResourceNode(groupId, nodes),
  );
  const nodes = [
    ...data.nodes.filter((node) => !nodeIdMap.has(node.id)),
    ...groupedNodes,
  ];

  const edgeGroups = d3.groups(
    data.edges.map((edge) => ({
      ...edge,
      source: nodeIdMap.get(edge.source) || edge.source,
      target: nodeIdMap.get(edge.target) || edge.target,
    })),
    (edge) => `${edge.source}->${edge.target}`,
  );

  return {
    ...data,
    nodes,
    edges: mergeEdges(edgeGroups),
    node_count: nodes.length,
    grouped_resource_count: groupedNodes.length,
  };
}

function stepResourceKey(step) {
  if (step.kind === "sg") return `${step.kind}:${step.detail?.sg_id || step.name}`;
  if (step.kind === "rt") {
    return [
      step.kind,
      step.detail?.route_table_id,
      step.detail?.target_kind,
      step.detail?.target,
    ]
      .filter(Boolean)
      .join(":");
  }
  if (step.kind === "node") return `${step.kind}:${step.detail?.id || step.name}`;
  if (step.kind === "tgw") return `${step.kind}:${stringify(step.detail)}`;
  if (step.kind === "elb") return `${step.kind}:${stringify(step.detail)}`;
  return `${step.kind}:${step.name}`;
}

function raySummary(rayInfo) {
  return {
    id: rayInfo.id,
    ray: rayInfo.label,
    packet_space: rayInfo.packetSpace,
    source: rayInfo.source,
    target: rayInfo.target,
  };
}

function addGroupedRay(item, rayInfo) {
  if (!item.rays.some((ray) => ray.id === rayInfo.id)) {
    item.rays.push(raySummary(rayInfo));
  }
}

function groupedEdgeLabel(edgeKind, rays) {
  if (rays.length <= 1) return edgeKind;
  return `${rays.length} rays ${edgeKind}`;
}

function appendRayStep(parent, step, rayInfo) {
  const resourceKey = stepResourceKey(step);
  let item = parent.children.find(
    (child) => child.kind === step.kind && child.resourceKey === resourceKey,
  );

  if (!item) {
    item = makeRayItem(
      `${parent.id}:${resourceKey}`,
      step.name,
      step.kind,
      step.detail,
      [],
      {
        id: `${parent.id}->${resourceKey}`,
        kind: step.edgeKind,
        label: step.edgeLabel,
        name: `${step.edgeLabel}: ${parent.name} -> ${step.name}`,
        rays: [],
        detail: {
          step: step.edgeKind,
          from: parent.name,
          to: step.name,
          detail: step.detail,
        },
      },
      resourceKey,
    );
    parent.children.push(item);
  }

  addGroupedRay(item, rayInfo);
  if (item.edge) {
    if (!item.edge.rays.some((ray) => ray.id === rayInfo.id)) {
      item.edge.rays.push(raySummary(rayInfo));
    }
    item.edge.label = groupedEdgeLabel(step.edgeKind, item.edge.rays);
    item.edge.detail = {
      step: step.edgeKind,
      from: parent.name,
      to: item.name,
      grouped_rays: item.edge.rays.length,
      rays: item.edge.rays,
      detail: step.detail,
    };
  }

  return item;
}

function buildRayTree({ direction, selectedNode, edges, nodesById }) {
  const root = makeRayItem(
    `root:${direction}:${selectedNode.id}`,
    conciseNodeLabel(selectedNode),
    "node",
    selectedNode,
    [],
  );

  edges.forEach((edge, edgeIndex) => {
    const peerId = direction === "outbound" ? edge.target : edge.source;
    const peer = nodesById.get(peerId);

    edge.paths.forEach((path, pathIndex) => {
      const rayLabel = `ray ${edgeIndex + 1}.${pathIndex + 1}`;
      const rayInfo = {
        id: `ray:${edge.id}:${pathIndex}`,
        label: rayLabel,
        packetSpace: path.packet_space,
        source: nodesById.get(edge.source)?.label || edge.source,
        target: nodesById.get(edge.target)?.label || edge.target,
      };
      const steps = [];

      if (direction === "outbound") {
        if (path.elb_target) {
          steps.push({
            id: `${rayInfo.id}:elb`,
            name: "elb target",
            kind: "elb",
            edgeKind: "elb",
            edgeLabel: `${rayLabel} elb`,
            detail: path.elb_target,
          });
        }
        if (path.egress_rule) {
          steps.push({
            id: `${rayInfo.id}:egress`,
            name: shortRuleLabel(path.egress_rule, "egress"),
            kind: "sg",
            edgeKind: "sg",
            edgeLabel: path.elb_target ? "sg" : `${rayLabel} sg`,
            detail: path.egress_rule,
          });
        }
        if (path.route) {
          steps.push({
            id: `${rayInfo.id}:route`,
            name: shortRouteLabel(path.route),
            kind: "rt",
            edgeKind: "rt",
            edgeLabel: "rt",
            detail: path.route,
          });
        }
        if (path.tgw_hop) {
          steps.push({
            id: `${rayInfo.id}:tgw`,
            name: "tgw hop",
            kind: "tgw",
            edgeKind: "tgw",
            edgeLabel: "tgw",
            detail: path.tgw_hop,
          });
        }
        if (path.ingress_rule) {
          steps.push({
            id: `${rayInfo.id}:ingress`,
            name: shortRuleLabel(path.ingress_rule, "ingress"),
            kind: "sg",
            edgeKind: "sg",
            edgeLabel: "sg",
            detail: path.ingress_rule,
          });
        }
      } else {
        if (path.ingress_rule) {
          steps.push({
            id: `${rayInfo.id}:ingress`,
            name: shortRuleLabel(path.ingress_rule, "ingress"),
            kind: "sg",
            edgeKind: "sg",
            edgeLabel: `${rayLabel} sg`,
            detail: path.ingress_rule,
          });
        }
        if (path.tgw_hop) {
          steps.push({
            id: `${rayInfo.id}:tgw`,
            name: "tgw hop",
            kind: "tgw",
            edgeKind: "tgw",
            edgeLabel: "tgw",
            detail: path.tgw_hop,
          });
        }
        if (path.route) {
          steps.push({
            id: `${rayInfo.id}:route`,
            name: shortRouteLabel(path.route),
            kind: "rt",
            edgeKind: "rt",
            edgeLabel: "rt",
            detail: path.route,
          });
        }
        if (path.egress_rule) {
          steps.push({
            id: `${rayInfo.id}:egress`,
            name: shortRuleLabel(path.egress_rule, "egress"),
            kind: "sg",
            edgeKind: "sg",
            edgeLabel: "sg",
            detail: path.egress_rule,
          });
        }
        if (path.elb_target) {
          steps.push({
            id: `${rayInfo.id}:elb`,
            name: "elb target",
            kind: "elb",
            edgeKind: "elb",
            edgeLabel: "elb",
            detail: path.elb_target,
          });
        }
      }

      steps.push({
        id: `${rayInfo.id}:peer`,
        name: nodeStepLabel(peer, peerId),
        kind: "node",
        edgeKind: "eni",
        edgeLabel: "eni",
        detail: peer || { id: peerId },
      });

      steps.reduce((parent, step) => appendRayStep(parent, step, rayInfo), root);
    });
  });

  return root;
}

function kindColor(kind) {
  return {
    node: "#38bdf8",
    sg: "#22c55e",
    rt: "#ef4444",
    tgw: "#a78bfa",
    elb: "#fb923c",
  }[kind] || "#94a3b8";
}

function edgeColor(kind) {
  return {
    sg: "#22c55e",
    rt: "#f59e0b",
    tgw: "#a78bfa",
    elb: "#fb923c",
    eni: "#38bdf8",
  }[kind] || "#64748b";
}

function addGuiActionRows(gui, settings) {
  [
    ["zoomIn", "chart-gui-action-zoom"],
    ["zoomOut", "chart-gui-action-zoom"],
    ["reset", "chart-gui-action-zoom"],
    ["exportPng", "chart-gui-action-export"],
    ["exportSvg", "chart-gui-action-export"],
  ].forEach(([property, className]) => {
    gui
      .add(settings, property)
      .name(
        {
          zoomIn: "+",
          zoomOut: "-",
          reset: "Reset",
          exportPng: "Export PNG",
          exportSvg: "Export SVG",
        }[property],
      )
      .domElement.classList.add("chart-gui-action", className);
  });
}

function BundleChart({
  data,
  nodesById,
  connectedNodeIds,
  hideIsolated,
  groupMultiEniResources,
  searchTerm,
  selectedNodeId,
  onHideIsolatedChange,
  onGroupMultiEniResourcesChange,
  onSelectNode,
  onVisibleCounts,
}) {
  const svgRef = useRef(null);
  const wrapRef = useRef(null);
  const guiRef = useRef(null);
  const zoomRef = useRef(null);
  const transformRef = useRef(d3.zoomIdentity);
  const guiActionsRef = useRef({});
  const guiControllersRef = useRef({});
  const visibleCountsRef = useRef(null);
  const guiCallbackRef = useRef({
    onHideIsolatedChange,
    onGroupMultiEniResourcesChange,
  });
  const guiStateRef = useRef({
    hideIsolated,
    groupMultiEniResources,
  });
  const bundleGuiSettingsRef = useRef({
    rotation: 0,
    hideIsolated: true,
    groupMultiEniResources: true,
  });
  const [chartRotation, setChartRotation] = useState(0);

  useEffect(() => {
    guiCallbackRef.current = {
      onHideIsolatedChange,
      onGroupMultiEniResourcesChange,
    };
    guiStateRef.current = {
      hideIsolated,
      groupMultiEniResources,
    };
  }, [groupMultiEniResources, hideIsolated, onGroupMultiEniResourcesChange, onHideIsolatedChange]);

  useEffect(() => {
    const container = guiRef.current;
    if (!container) return undefined;

    const gui = new GUI({ title: "Bundle chart" });
    container.replaceChildren(gui.domElement);

    const settings = bundleGuiSettingsRef.current;
    settings.rotation = chartRotation;
    settings.hideIsolated = hideIsolated;
    settings.groupMultiEniResources = groupMultiEniResources;
    settings.zoomIn = () => guiActionsRef.current.zoomIn?.();
    settings.zoomOut = () => guiActionsRef.current.zoomOut?.();
    settings.reset = () => guiActionsRef.current.reset?.();
    settings.exportPng = () => guiActionsRef.current.exportPng?.();
    settings.exportSvg = () => guiActionsRef.current.exportSvg?.();

    guiControllersRef.current.rotation = gui
      .add(settings, "rotation", -180, 180, 1)
      .name("Rotation")
      .onChange((value) => {
        setChartRotation(Number(value));
      });
    guiControllersRef.current.hideIsolated = gui
      .add(settings, "hideIsolated")
      .name("Hide ENIs without rays")
      .onChange((value) => {
        const nextValue = Boolean(value);
        if (guiStateRef.current.hideIsolated === nextValue) return;
        guiStateRef.current.hideIsolated = nextValue;
        guiCallbackRef.current.onHideIsolatedChange(nextValue);
      });
    guiControllersRef.current.groupMultiEniResources = gui
      .add(settings, "groupMultiEniResources")
      .name("Group resources with many ENIs")
      .onChange((value) => {
        const nextValue = Boolean(value);
        if (guiStateRef.current.groupMultiEniResources === nextValue) return;
        guiStateRef.current.groupMultiEniResources = nextValue;
        guiCallbackRef.current.onGroupMultiEniResourcesChange(nextValue);
      });
    addGuiActionRows(gui, settings);

    return () => {
      gui.destroy();
      guiControllersRef.current = {};
      container.replaceChildren();
    };
  }, []);

  useEffect(() => {
    const settings = bundleGuiSettingsRef.current;
    settings.hideIsolated = hideIsolated;
    settings.groupMultiEniResources = groupMultiEniResources;
    guiControllersRef.current.hideIsolated?.updateDisplay();
    guiControllersRef.current.groupMultiEniResources?.updateDisplay();
  }, [groupMultiEniResources, hideIsolated]);

  useLayoutEffect(() => {
    const svgElement = svgRef.current;
    const wrapElement = wrapRef.current;
    if (!svgElement || !wrapElement) return undefined;

    const render = () => {
      const visibleNodes = data.nodes.filter(
        (node) => !hideIsolated || connectedNodeIds.has(node.id),
      );
      const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
      const isolatedCount = visibleNodes.filter(
        (node) => !connectedNodeIds.has(node.id),
      ).length;
      const rect = wrapElement.getBoundingClientRect();
      const width = Math.max(720, rect.width);
      const height = Math.max(720, rect.height);
      const radius = Math.min(width, height) / 2;
      const innerRadius = radius - 165;

      const svg = d3.select(svgElement);
      svg.selectAll("*").remove();
      svg
        .attr("viewBox", `${-width / 2} ${-height / 2} ${width} ${height}`)
        .attr("width", width)
        .attr("height", height)
        .style("cursor", "grab");

      const viewport = svg
        .append("g")
        .attr("class", "chart-viewport")
        .attr("transform", transformRef.current.toString());

      const zoom = d3
        .zoom()
        .scaleExtent([0.25, 6])
        .on("start", () => {
          svg.style("cursor", "grabbing");
        })
        .on("zoom", (event) => {
          transformRef.current = event.transform;
          viewport.attr("transform", event.transform.toString());
        })
        .on("end", () => {
          svg.style("cursor", "grab");
        });
      zoomRef.current = zoom;
      svg.call(zoom).call(zoom.transform, transformRef.current);

      viewport
        .append("rect")
        .attr("class", "zoom-hitbox")
        .attr("x", -50000)
        .attr("y", -50000)
        .attr("width", 100000)
        .attr("height", 100000)
        .on("click", () => onSelectNode(null));

      const chartLayer = viewport.append("g").attr("class", "bundle-chart-layer");
      const rotationRadians = (chartRotation * Math.PI) / 180;
      const rotatedAngle = (angle) =>
        (angle + rotationRadians + Math.PI * 2) % (Math.PI * 2);
      const radialTransform = (node, radiusOffset = 0) =>
        `rotate(${(rotatedAngle(node.x) * 180) / Math.PI - 90}) translate(${
          node.y + radiusOffset
        },0)`;
      const isLeftSide = (node) => rotatedAngle(node.x) >= Math.PI;

      const root = d3.cluster().size([2 * Math.PI, innerRadius])(
        d3
          .hierarchy(buildVisibleHierarchy(visibleNodes))
          .sort(
            (a, b) =>
              d3.ascending(a.data.sort_key || a.data.name, b.data.sort_key || b.data.name),
          ),
      );
      const leaves = root.leaves();
      const leavesById = new Map(leaves.map((leaf) => [leaf.data.node_id, leaf]));
      const accountSpans = d3
        .groups(
          leaves.filter(
            (leaf) => !leaf.data.is_account_separator && !leaf.data.is_account_spacer,
          ),
          (leaf) => nodeAccountId(nodesById.get(leaf.data.node_id)),
        )
        .map(([accountId, accountLeaves], index) => {
          const angles = accountLeaves.map((leaf) => leaf.x);
          return {
            accountId,
            startAngle: Math.max(0, d3.min(angles) - 0.015),
            endAngle: Math.min(Math.PI * 2, d3.max(angles) + 0.015),
            color: ACCOUNT_PALETTE[index % ACCOUNT_PALETTE.length],
          };
        });
      const defs = svg.append("defs");
      accountSpans.forEach((span) => {
        const gradient = defs
          .append("radialGradient")
          .attr("id", `account-glow-${hashString(span.accountId)}`)
          .attr("gradientUnits", "userSpaceOnUse")
          .attr("cx", 0)
          .attr("cy", 0)
          .attr("r", innerRadius + 145);
        gradient.append("stop").attr("offset", "0%").attr("stop-color", span.color).attr("stop-opacity", 0);
        gradient.append("stop").attr("offset", "62%").attr("stop-color", span.color).attr("stop-opacity", 0.16);
        gradient.append("stop").attr("offset", "100%").attr("stop-color", span.color).attr("stop-opacity", 0);
      });
      const accountArc = d3
        .arc()
        .innerRadius(innerRadius + 6)
        .outerRadius(innerRadius + 128)
        .startAngle((d) => d.startAngle)
        .endAngle((d) => d.endAngle);

      const line = d3
        .lineRadial()
        .curve(d3.curveBundle.beta(0.85))
        .radius((point) => point.y)
        .angle((point) => rotatedAngle(point.x));

      const bundledEdges = data.edges
        .filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target))
        .map((edge) => {
          const source = leavesById.get(edge.source);
          const target = leavesById.get(edge.target);
          return source && target ? { source, target, edge } : null;
        })
        .filter(Boolean);
      const selectedDestinationIds = new Set(
        selectedNodeId
          ? bundledEdges
              .filter((link) => link.edge.source === selectedNodeId)
              .map((link) => link.edge.target)
          : [],
      );

      chartLayer
        .append("g")
        .attr("class", "account-glow-layer")
        .attr("transform", `rotate(${chartRotation})`)
        .selectAll("path")
        .data(accountSpans)
        .join("path")
        .attr("class", "account-glow")
        .attr("d", accountArc)
        .attr("fill", (d) => `url(#account-glow-${hashString(d.accountId)})`);

      chartLayer
        .append("g")
        .attr("fill", "none")
        .selectAll("path")
        .data(bundledEdges)
        .join("path")
        .attr(
          "class",
          (link) =>
            `link${link.edge.wildcard ? " wildcard" : link.edge.broad_ingress ? " broad" : ""}${
              link.edge.source === selectedNodeId ? " selected" : selectedNodeId ? " dimmed" : ""
            }`,
        )
        .attr("stroke-width", (link) => link.edge.width)
        .attr("d", (link) => line(link.source.path(link.target)))
        .on("click", (event, link) => {
          event.stopPropagation();
          onSelectNode(link.edge.source);
        });

      chartLayer
        .append("g")
        .selectAll("circle")
        .data(
          leaves.filter(
            (leaf) => !leaf.data.is_account_separator && !leaf.data.is_account_spacer,
          ),
        )
        .join("circle")
        .attr("class", (leaf) => {
          const node = nodesById.get(leaf.data.node_id);
          const selected = leaf.data.node_id === selectedNodeId ? " selected" : "";
          const isolated = connectedNodeIds.has(leaf.data.node_id) ? "" : " isolated";
          const dimmed =
            searchTerm &&
            node &&
            !JSON.stringify(node).toLowerCase().includes(searchTerm)
              ? " dimmed"
              : "";
          return `node-dot${selected}${isolated}${dimmed}`;
        })
        .attr("transform", (d) => radialTransform(d))
        .attr("r", (d) => (d.data.node_id === selectedNodeId ? 4.8 : 3.2))
        .attr("fill", (d) => {
          const node = nodesById.get(d.data.node_id);
          return resourceColor(effectiveResourceType(node));
        })
        .on("click", (event, d) => {
          event.stopPropagation();
          onSelectNode(d.data.node_id);
        })
        .append("title")
        .text((d) => {
          const node = nodesById.get(d.data.node_id);
          const suffix = connectedNodeIds.has(d.data.node_id)
            ? ""
            : " (no exported rays)";
          return `${node?.label || d.data.node_id}${suffix}`;
        });

      chartLayer
        .append("g")
        .selectAll("text")
        .data(leaves)
        .join("text")
        .attr("class", (leaf) => {
          if (leaf.data.is_account_spacer || leaf.data.is_account_separator) {
            return "account-spacer-label";
          }
          const node = nodesById.get(leaf.data.node_id);
          const selected = leaf.data.node_id === selectedNodeId ? " selected" : "";
          const destination =
            selectedNodeId && selectedDestinationIds.has(leaf.data.node_id)
              ? " destination"
              : "";
          const dimmed =
            searchTerm &&
            node &&
            !JSON.stringify(node).toLowerCase().includes(searchTerm)
              ? " dimmed"
              : "";
          return `node-label${selected}${destination}${dimmed}`;
        })
        .attr("dy", "0.31em")
        .attr(
          "transform",
          (d) => `${radialTransform(d, 8)}${isLeftSide(d) ? " rotate(180)" : ""}`,
        )
        .attr("text-anchor", (d) => (isLeftSide(d) ? "end" : "start"))
        .attr("fill", (d) => {
          if (d.data.is_account_spacer || d.data.is_account_separator) return "transparent";
          const node = nodesById.get(d.data.node_id);
          return resourceColor(effectiveResourceType(node));
        })
        .text((d) => (d.data.is_account_separator || d.data.is_account_spacer ? "" : d.data.name))
        .on("click", (event, d) => {
          if (d.data.is_account_spacer) return;
          if (d.data.is_account_separator) return;
          event.stopPropagation();
          onSelectNode(d.data.node_id);
        })
        .append("title")
        .text((d) => {
          if (d.data.is_account_spacer) return "";
          if (d.data.is_account_separator) return "";
          const node = nodesById.get(d.data.node_id);
          return node?.label || d.data.node_id;
        });

      const nextVisibleCounts = {
        nodes: visibleNodes.length,
        edges: bundledEdges.length,
        isolated: isolatedCount,
      };
      const currentVisibleCounts = visibleCountsRef.current;
      if (
        !currentVisibleCounts ||
        currentVisibleCounts.nodes !== nextVisibleCounts.nodes ||
        currentVisibleCounts.edges !== nextVisibleCounts.edges ||
        currentVisibleCounts.isolated !== nextVisibleCounts.isolated
      ) {
        visibleCountsRef.current = nextVisibleCounts;
        window.requestAnimationFrame(() => {
          onVisibleCounts(
            nextVisibleCounts.nodes,
            nextVisibleCounts.edges,
            nextVisibleCounts.isolated,
          );
        });
      }
    };

    render();
    const observer = new ResizeObserver(render);
    observer.observe(wrapElement);
    return () => observer.disconnect();
  }, [
    connectedNodeIds,
    chartRotation,
    data,
    hideIsolated,
    nodesById,
    onSelectNode,
    onVisibleCounts,
    searchTerm,
    selectedNodeId,
  ]);

  const zoomBy = useCallback((scaleFactor) => {
    const svgElement = svgRef.current;
    const zoom = zoomRef.current;
    if (!svgElement || !zoom) return;
    d3.select(svgElement)
      .transition()
      .duration(180)
      .call(zoom.scaleBy, scaleFactor);
  }, []);

  const resetZoom = useCallback(() => {
    const svgElement = svgRef.current;
    const zoom = zoomRef.current;
    if (!svgElement || !zoom) return;
    transformRef.current = d3.zoomIdentity;
    d3.select(svgElement)
      .transition()
      .duration(180)
      .call(zoom.transform, d3.zoomIdentity);
  }, []);

  const exportPng = useCallback(async () => {
    await exportSvgAsPng(svgRef.current, "packet-paths-chart-4000.png");
  }, []);

  const exportSvgFile = useCallback(() => {
    exportSvg(svgRef.current, "packet-paths-chart.svg");
  }, []);

  guiActionsRef.current = {
    zoomIn: () => zoomBy(1.25),
    zoomOut: () => zoomBy(0.8),
    reset: resetZoom,
    exportPng,
    exportSvg: exportSvgFile,
  };

  return (
    <main id="chart-wrap" ref={wrapRef}>
      <svg id="chart" ref={svgRef} />
      <div className="chart-gui" ref={guiRef} />
      <div className="banner">
        Click an ENI on the circle to inspect outbound rays. Curves are
        ENI-to-ENI packet-space reachability.
      </div>
    </main>
  );
}

function RayTreeChart({ treeData, direction, selectedItemId, onSelectItem }) {
  const svgRef = useRef(null);
  const wrapRef = useRef(null);
  const guiRef = useRef(null);
  const zoomRef = useRef(null);
  const transformRef = useRef(d3.zoomIdentity);
  const guiActionsRef = useRef({});
  const guiSettingsRef = useRef({
    textAngle: 20,
    horizontalDistance: 230,
    verticalDistance: 25,
  });
  const [textAngle, setTextAngle] = useState(20);
  const [horizontalDistance, setHorizontalDistance] = useState(230);
  const [verticalDistance, setVerticalDistance] = useState(25);

  useEffect(() => {
    const container = guiRef.current;
    if (!container) return undefined;

    const gui = new GUI({ title: "Flow chart" });
    gui.domElement.classList.add("ray-gui-panel");
    container.replaceChildren(gui.domElement);

    const settings = guiSettingsRef.current;
    settings.textAngle = textAngle;
    settings.horizontalDistance = horizontalDistance;
    settings.verticalDistance = verticalDistance;
    settings.zoomIn = () => guiActionsRef.current.zoomIn?.();
    settings.zoomOut = () => guiActionsRef.current.zoomOut?.();
    settings.reset = () => guiActionsRef.current.reset?.();
    settings.exportPng = () => guiActionsRef.current.exportPng?.();
    settings.exportSvg = () => guiActionsRef.current.exportSvg?.();

    gui
      .add(settings, "textAngle", -90, 90, 1)
      .name("Text angle")
      .onChange((value) => {
        setTextAngle(Number(value));
      });
    gui
      .add(settings, "horizontalDistance", 120, 420, 10)
      .name("Node distance")
      .onChange((value) => {
        setHorizontalDistance(Number(value));
      });
    gui
      .add(settings, "verticalDistance", 14, 60, 1)
      .name("Vertical distance")
      .onChange((value) => {
        setVerticalDistance(Number(value));
      });
    addGuiActionRows(gui, settings);

    return () => {
      gui.destroy();
      container.replaceChildren();
    };
  }, []);

  useLayoutEffect(() => {
    const svgElement = svgRef.current;
    const wrapElement = wrapRef.current;
    if (!svgElement || !wrapElement || !treeData) return undefined;

    const render = () => {
      const rect = wrapElement.getBoundingClientRect();
      const width = Math.max(760, rect.width);
      const dx = verticalDistance;
      const dy = horizontalDistance;
      const root = d3.hierarchy(treeData);
      const tree = d3.tree().nodeSize([dx, dy]);
      root.sort((a, b) => d3.ascending(a.data.name, b.data.name));
      tree(root);

      let x0 = Infinity;
      let x1 = -Infinity;
      let y1 = 0;
      root.each((node) => {
        if (node.x > x1) x1 = node.x;
        if (node.x < x0) x0 = node.x;
        if (node.y > y1) y1 = node.y;
      });

      const height = Math.max(720, x1 - x0 + dx * 6);
      const chartWidth = Math.max(width, y1 + 420);
      const isInbound = direction === "inbound";
      const nodeX = (node) => (isInbound ? y1 - node.y : node.y);
      const svg = d3.select(svgElement);
      svg.selectAll("*").remove();
      svg
        .attr("viewBox", `${-120} ${x0 - dx * 3} ${chartWidth + 180} ${height}`)
        .attr("width", width)
        .attr("height", Math.max(720, rect.height))
        .style("cursor", "grab");

      const viewport = svg
        .append("g")
        .attr("class", "chart-viewport")
        .attr("transform", transformRef.current.toString());

      const zoom = d3
        .zoom()
        .scaleExtent([0.25, 6])
        .on("start", () => {
          svg.style("cursor", "grabbing");
        })
        .on("zoom", (event) => {
          transformRef.current = event.transform;
          viewport.attr("transform", event.transform.toString());
        })
        .on("end", () => {
          svg.style("cursor", "grab");
        });
      zoomRef.current = zoom;
      svg.call(zoom).call(zoom.transform, transformRef.current);

      viewport
        .append("rect")
        .attr("class", "zoom-hitbox")
        .attr("x", -50000)
        .attr("y", -50000)
        .attr("width", 100000)
        .attr("height", 100000);

      viewport
        .append("g")
        .selectAll("path")
        .data(root.links())
        .join("path")
        .attr(
          "class",
          (d) => `ray-tree-link${d.target.data.edge?.id === selectedItemId ? " selected" : ""}`,
        )
        .attr("fill", "none")
        .attr("stroke", (d) =>
          d.target.data.edge?.id === selectedItemId
            ? "#22c55e"
            : edgeColor(d.target.data.edge?.kind),
        )
        .attr("stroke-opacity", (d) => (d.target.data.edge?.id === selectedItemId ? 1 : 0.78))
        .attr("stroke-width", (d) => {
          const rayCount = d.target.data.edge?.rays?.length || 1;
          return Math.min(7, 1.5 + Math.log2(rayCount + 1));
        })
        .attr("stroke-linecap", "round")
        .attr("stroke-linejoin", "round")
        .attr(
          "d",
          d3
            .linkHorizontal()
            .x((d) => nodeX(d))
            .y((d) => d.x),
        )
        .on("click", (event, d) => {
          event.stopPropagation();
          if (d.target.data.edge) onSelectItem(d.target.data.edge);
        })
        .append("title")
        .text((d) => d.target.data.edge?.name || "");

      const node = viewport
        .append("g")
        .attr("stroke-linejoin", "round")
        .selectAll("g")
        .data(root.descendants())
        .join("g")
        .attr(
          "class",
          (d) => `ray-tree-node${d.data.id === selectedItemId ? " selected" : ""}`,
        )
        .attr("transform", (d) => `translate(${nodeX(d)},${d.x})`)
        .on("click", (event, d) => {
          event.stopPropagation();
          onSelectItem(d.data);
        });

      node
        .append("circle")
        .attr("fill", (d) => kindColor(d.data.kind))
        .attr("r", (d) => (d.data.id === selectedItemId ? 5 : 3.5));

      node
        .append("text")
        .attr("class", "ray-tree-label")
        .attr("dy", "0.31em")
        .attr("x", (d) => {
          const leftOfNode = isInbound ? !d.children : d.children;
          return leftOfNode ? -8 : 8;
        })
        .attr("text-anchor", (d) => {
          const leftOfNode = isInbound ? !d.children : d.children;
          return leftOfNode ? "end" : "start";
        })
        .attr("transform", `rotate(${textAngle})`)
        .text((d) => d.data.name)
        .append("title")
        .text((d) => d.data.name);
    };

    render();
    const observer = new ResizeObserver(render);
    observer.observe(wrapElement);
    return () => observer.disconnect();
  }, [
    direction,
    horizontalDistance,
    onSelectItem,
    selectedItemId,
    textAngle,
    treeData,
    verticalDistance,
  ]);

  const zoomBy = useCallback((scaleFactor) => {
    const svgElement = svgRef.current;
    const zoom = zoomRef.current;
    if (!svgElement || !zoom) return;
    d3.select(svgElement)
      .transition()
      .duration(180)
      .call(zoom.scaleBy, scaleFactor);
  }, []);

  const resetZoom = useCallback(() => {
    const svgElement = svgRef.current;
    const zoom = zoomRef.current;
    if (!svgElement || !zoom) return;
    transformRef.current = d3.zoomIdentity;
    d3.select(svgElement)
      .transition()
      .duration(180)
      .call(zoom.transform, d3.zoomIdentity);
  }, []);

  const exportPng = useCallback(async () => {
    await exportSvgAsPng(svgRef.current, "packet-path-rays-4000.png");
  }, []);

  const exportSvgFile = useCallback(() => {
    exportSvg(svgRef.current, "packet-path-rays.svg");
  }, []);

  guiActionsRef.current = {
    zoomIn: () => zoomBy(1.25),
    zoomOut: () => zoomBy(0.8),
    reset: resetZoom,
    exportPng,
    exportSvg: exportSvgFile,
  };

  return (
    <main id="chart-wrap" ref={wrapRef}>
      <svg id="chart" ref={svgRef} />
      <div className="chart-gui" ref={guiRef} />
      <div className="banner">
        Select any hop node or ray edge to inspect it.
      </div>
    </main>
  );
}

function GroupedRays({ rays }) {
  if (!rays?.length) return null;
  return (
    <>
      <h2>Grouped Rays</h2>
      <div className="grouped-rays">
        {rays.map((ray) => (
          <div className="ray" key={ray.id}>
            <div>
              <b>{ray.ray}</b> {ray.source} {"->"} {ray.target}
            </div>
            <div>
              <b>packet</b> {stringify(ray.packet_space)}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

function RayItemDetails({ item, selectedNode, direction, edgeCount }) {
  if (!item) {
    return (
      <section id="details">
        <h1>{direction === "outbound" ? "Outbound" : "Inbound"} Rays</h1>
        <p className="muted">
          {edgeCount} connection{edgeCount === 1 ? "" : "s"} for {selectedNode.label}.
        </p>
      </section>
    );
  }

  return (
    <section id="details">
      <h1>{item.name}</h1>
      <div className="pillrow">
        <span className="pill">{item.kind}</span>
        {item.rays?.length ? (
          <span className="pill">
            {item.rays.length} ray{item.rays.length === 1 ? "" : "s"}
          </span>
        ) : null}
        {item.detail?.grouped_rays ? (
          <span className="pill">
            {item.detail.grouped_rays} ray{item.detail.grouped_rays === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>
      {keyValueRows(item.detail?.detail || item.detail || {})}
      <GroupedRays rays={item.rays || item.detail?.rays} />
    </section>
  );
}

function RayPage({ data, nodesById, edgesBySource, edgesByTarget, route }) {
  const selectedNode = nodesById.get(route.nodeId);
  const direction = route.direction;
  const edges =
    direction === "outbound"
      ? edgesBySource.get(route.nodeId) || []
      : edgesByTarget.get(route.nodeId) || [];
  const treeData = useMemo(
    () =>
      selectedNode
        ? buildRayTree({ direction, selectedNode, edges, nodesById })
        : null,
    [direction, edges, nodesById, selectedNode],
  );
  const [selectedItem, setSelectedItem] = useState(treeData);

  useEffect(() => {
    setSelectedItem(treeData);
  }, [treeData]);

  if (!selectedNode) {
    return (
      <div className="load-state">
        Unknown selected node.{" "}
        <button type="button" onClick={() => pushRoute("/")}>
          Back to bundle chart
        </button>
      </div>
    );
  }

  return (
    <div id="app">
      <RayTreeChart
        treeData={treeData}
        direction={direction}
        selectedItemId={selectedItem?.id}
        onSelectItem={setSelectedItem}
      />
      <aside id="panel">
        <div className="toolbar">
          <button type="button" onClick={() => pushRoute(bundlePath(selectedNode.id))}>
            Back to bundle chart
          </button>
          <button
            type="button"
            onClick={() => pushRoute(raysPath(direction === "outbound" ? "inbound" : "outbound", selectedNode.id))}
          >
            Show {direction === "outbound" ? "inbound" : "outbound"} rays
          </button>
        </div>
        <div className="stats">
          <div className="stat">
            <b>{edges.length}</b>
            <span>connections</span>
          </div>
          <div className="stat">
            <b>{d3.sum(edges, (edge) => edge.path_count || edge.paths?.length || 0)}</b>
            <span>paths</span>
          </div>
          <div className="stat">
            <b>{direction}</b>
            <span>direction</span>
          </div>
          <div className="stat">
            <b>{data.node_count}</b>
            <span>ENIs</span>
          </div>
        </div>
        <RayItemDetails
          item={selectedItem}
          selectedNode={selectedNode}
          direction={direction}
          edgeCount={edges.length}
        />
      </aside>
    </div>
  );
}

export function App() {
  const [route, setRoute] = useState(readRoute);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [hideIsolated, setHideIsolated] = useState(true);
  const [groupMultiEniResources, setGroupMultiEniResources] = useState(true);
  const [selectedNodeId, setSelectedNodeId] = useState(route.nodeId);
  const [visibleCounts, setVisibleCounts] = useState({ nodes: 0, edges: 0 });

  useEffect(() => {
    const handlePopState = () => setRoute(readRoute());
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    fetch(DATA_URL)
      .then((response) => {
        if (!response.ok) throw new Error(`Unable to load ${DATA_URL}`);
        return response.json();
      })
      .then(setData)
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    if (route.page === "bundle") {
      setSelectedNodeId(route.nodeId);
    }
  }, [route]);

  const rawNodesById = useMemo(
    () => new Map((data?.nodes || []).map((node) => [node.id, node])),
    [data],
  );
  const rawEdgesBySource = useMemo(
    () => d3.group(data?.edges || [], (edge) => edge.source),
    [data],
  );
  const rawEdgesByTarget = useMemo(
    () => d3.group(data?.edges || [], (edge) => edge.target),
    [data],
  );
  const bundleData = useMemo(
    () => (data ? buildBundleViewData(data, groupMultiEniResources) : null),
    [data, groupMultiEniResources],
  );
  const nodesById = useMemo(
    () => new Map((bundleData?.nodes || []).map((node) => [node.id, node])),
    [bundleData],
  );
  const edgesBySource = useMemo(
    () => d3.group(bundleData?.edges || [], (edge) => edge.source),
    [bundleData],
  );
  const edgesByTarget = useMemo(
    () => d3.group(bundleData?.edges || [], (edge) => edge.target),
    [bundleData],
  );
  const connectedNodeIds = useMemo(
    () => new Set((bundleData?.edges || []).flatMap((edge) => [edge.source, edge.target])),
    [bundleData],
  );
  const selectedNode = selectedNodeId ? nodesById.get(selectedNodeId) : null;
  const outgoing = selectedNodeId ? edgesBySource.get(selectedNodeId) || [] : [];
  const incoming = selectedNodeId ? edgesByTarget.get(selectedNodeId) || [] : [];
  const searchTerm = search.trim().toLowerCase();
  const handleVisibleCounts = useCallback((nodes, edges, isolated) => {
    setVisibleCounts((current) =>
      current.nodes === nodes && current.edges === edges && current.isolated === isolated
        ? current
        : { nodes, edges, isolated },
    );
  }, []);

  useEffect(() => {
    // Wait for the data: otherwise a ?node= deep link is cleared before it can resolve.
    if (!bundleData) return;
    if (hideIsolated && selectedNodeId && !connectedNodeIds.has(selectedNodeId)) {
      setSelectedNodeId(null);
    }
    if (selectedNodeId && !nodesById.has(selectedNodeId)) {
      setSelectedNodeId(null);
    }
  }, [bundleData, connectedNodeIds, hideIsolated, nodesById, selectedNodeId]);

  const handleHideIsolatedChange = useCallback((value) => {
    setHideIsolated(value);
  }, []);

  const handleGroupMultiEniResourcesChange = useCallback((value) => {
    setGroupMultiEniResources(value);
  }, []);

  if (error) {
    return <div className="load-state">Failed to load bundle data: {error}</div>;
  }
  if (!data) {
    return <div className="load-state">Loading bundle data...</div>;
  }

  if (route.page === "rays") {
    return (
      <RayPage
        data={data}
        nodesById={rawNodesById}
        edgesBySource={rawEdgesBySource}
        edgesByTarget={rawEdgesByTarget}
        route={route}
      />
    );
  }

  return (
    <div id="app">
      <BundleChart
        data={bundleData}
        nodesById={nodesById}
        connectedNodeIds={connectedNodeIds}
        hideIsolated={hideIsolated}
        groupMultiEniResources={groupMultiEniResources}
        searchTerm={searchTerm}
        selectedNodeId={selectedNodeId}
        onHideIsolatedChange={handleHideIsolatedChange}
        onGroupMultiEniResourcesChange={handleGroupMultiEniResourcesChange}
        onSelectNode={(nodeId) => {
          setSelectedNodeId(nodeId);
          window.history.replaceState({}, "", bundlePath(nodeId));
        }}
        onVisibleCounts={handleVisibleCounts}
      />
      <aside id="panel">
        <div className="toolbar">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            type="search"
            placeholder="Filter ENIs, IPs, groups"
          />
          <button
            type="button"
            onClick={() => {
              setSearch("");
              setHideIsolated(false);
              setGroupMultiEniResources(false);
              setSelectedNodeId(null);
            }}
          >
            Reset
          </button>
        </div>
        <div className="stats">
          <div className="stat">
            <b>{visibleCounts.nodes}</b>
            <span>ENIs</span>
          </div>
          <div className="stat">
            <b>{visibleCounts.isolated || 0}</b>
            <span>without rays</span>
          </div>
          <div className="stat">
            <b>{visibleCounts.edges}</b>
            <span>connections</span>
          </div>
          <div className="stat">
            <b>{data.path_count}</b>
            <span>paths</span>
          </div>
        </div>
        <Details
          node={selectedNode}
          outgoing={outgoing}
          incoming={incoming}
          nodesById={nodesById}
          onShowOutbound={() => pushRoute(raysPath("outbound", selectedNode.id))}
          onShowInbound={() => pushRoute(raysPath("inbound", selectedNode.id))}
        />
      </aside>
    </div>
  );
}
