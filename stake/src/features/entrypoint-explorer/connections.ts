/** One-hop display context uses only supplied edges; it never creates relationships. */
export function connectionContext(nodeIds: string[], edges: Array<{ id: string; source: string; target: string }>, selected: string) {
  const known = new Set(nodeIds);
  const selectedEdge = edges.find(edge => edge.id === selected);
  const anchors = new Set(selectedEdge ? [selectedEdge.source, selectedEdge.target] : known.has(selected) ? [selected] : []);
  const nodes = new Set([...anchors].filter(id => known.has(id)));
  const links = new Set<string>();
  for (const edge of edges) {
    if (!known.has(edge.source) || !known.has(edge.target)) continue;
    if (selectedEdge ? edge.id === selectedEdge.id : anchors.has(edge.source) || anchors.has(edge.target)) {
      nodes.add(edge.source); nodes.add(edge.target); links.add(edge.id);
    }
  }
  return { nodes, edges: links };
}
