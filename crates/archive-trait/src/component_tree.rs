//! Component-oriented path storage shared by archive building and extraction.

use std::{borrow::Borrow, collections::HashMap, hash::Hash};

/// A stable index into a [`ComponentTree`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct NodeId(usize);

/// The sentinel root of every [`ComponentTree`].
pub(crate) const ROOT_NODE: NodeId = NodeId(0);

/// One structurally stored path component.
///
/// Component text lives in the parent node's `children` map, so a path with N
/// components retains N component names rather than N complete textual prefixes.
#[derive(Clone, Debug)]
struct ComponentNode<C, S> {
    parent: Option<NodeId>,
    state: Option<S>,
    children: HashMap<C, NodeId>,
    active_children: usize,
}

impl<C, S> ComponentNode<C, S> {
    fn root(state: Option<S>) -> Self {
        Self {
            parent: None,
            state,
            children: HashMap::new(),
            active_children: 0,
        }
    }

    fn child(parent: NodeId) -> Self {
        Self {
            parent: Some(parent),
            state: None,
            children: HashMap::new(),
            active_children: 0,
        }
    }
}

/// Path state stored as an arena of component edges and stable node IDs.
#[derive(Clone, Debug)]
pub(crate) struct ComponentTree<C, S> {
    nodes: Vec<ComponentNode<C, S>>,
}

impl<C, S> ComponentTree<C, S>
where
    C: Eq + Hash,
{
    pub(crate) fn new(root_state: Option<S>) -> Self {
        Self {
            nodes: vec![ComponentNode::root(root_state)],
        }
    }

    pub(crate) fn child<Q>(&self, parent: NodeId, component: &Q) -> Option<NodeId>
    where
        C: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.nodes.get(parent.0)?.children.get(component).copied()
    }

    pub(crate) fn ensure_child_with<Q, F>(
        &mut self,
        parent: NodeId,
        component: &Q,
        create_component: F,
    ) -> NodeId
    where
        C: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
        F: FnOnce() -> C,
    {
        if let Some(node) = self.child(parent, component) {
            return node;
        }

        let node = NodeId(self.nodes.len());
        self.nodes.push(ComponentNode::child(parent));
        // `parent` is either the root or an ID previously returned by this tree.
        self.nodes[parent.0]
            .children
            .insert(create_component(), node);
        node
    }

    pub(crate) fn state(&self, node: NodeId) -> Option<&S> {
        self.nodes.get(node.0).and_then(|node| node.state.as_ref())
    }

    pub(crate) fn set_state(&mut self, node: NodeId, state: S) {
        let Some(node) = self.nodes.get_mut(node.0) else {
            return;
        };
        let activate = node.state.replace(state).is_none();
        let parent = node.parent;
        if activate
            && let Some(parent) = parent
            && let Some(parent) = self.nodes.get_mut(parent.0)
        {
            parent.active_children += 1;
        }
    }

    pub(crate) fn clear_state(&mut self, node: NodeId) {
        let Some(node) = self.nodes.get_mut(node.0) else {
            return;
        };
        let deactivate = node.state.take().is_some();
        let parent = node.parent;
        if deactivate
            && let Some(parent) = parent
            && let Some(parent) = self.nodes.get_mut(parent.0)
        {
            parent.active_children -= 1;
        }
    }

    pub(crate) fn has_active_children(&self, node: NodeId) -> bool {
        self.nodes
            .get(node.0)
            .is_some_and(|node| node.active_children != 0)
    }

    #[cfg(test)]
    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(test)]
    pub(crate) fn components(&self) -> impl Iterator<Item = &C> {
        self.nodes.iter().flat_map(|node| node.children.keys())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_active_direct_children() {
        let mut tree = ComponentTree::<Box<str>, u8>::new(Some(0));
        let directory = tree.ensure_child_with(ROOT_NODE, "directory", || "directory".into());
        let child = tree.ensure_child_with(directory, "child", || "child".into());

        tree.set_state(directory, 1);
        assert!(tree.has_active_children(ROOT_NODE));
        tree.set_state(directory, 2);
        assert!(tree.has_active_children(ROOT_NODE));

        tree.set_state(child, 3);
        assert!(tree.has_active_children(directory));
        tree.clear_state(child);
        assert!(!tree.has_active_children(directory));

        tree.clear_state(directory);
        assert!(!tree.has_active_children(ROOT_NODE));
    }
}
