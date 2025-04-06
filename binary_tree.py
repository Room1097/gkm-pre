import matplotlib.pyplot as plt
import networkx as nx
from Crypto.PublicKey import RSA
import os

class Node:
    def __init__(self, identifier, encryption_key, decryption_key):
        self.data = {
            "identifier": identifier,
            "encryption_key": encryption_key,
            "decryption_key": decryption_key
        }
        self.left = None
        self.right = None
        self.left_re_encryption_key = None
        self.right_re_encryption_key = None
        self.parent = None
        self.is_left = None

def generate_sample_keys(index):
    return f"enc_key_{index}", f"dec_key_{index}"

def generate_keys():
    key_pair = RSA.generate(1024)
    encryption_key = key_pair.publickey().export_key().decode()
    decryption_key = key_pair.export_key().decode()
    return encryption_key, decryption_key

def build_full_binary_tree(height):
    if height < 1:
        return None

    total_nodes = 2**(height + 1) - 1  # Full binary tree node count
    nodes = []

    for i in range(total_nodes):
        enc, dec = generate_keys()
        node = Node(f"node_{i}", enc, dec)
        nodes.append(node)

    for i in range((total_nodes - 1) // 2):  # Only internal nodes get children
        left_index = 2 * i + 1
        right_index = 2 * i + 2

        nodes[i].left = nodes[left_index]
        nodes[left_index].parent = nodes[i]
        nodes[left_index].is_left = True

        nodes[i].right = nodes[right_index]
        nodes[right_index].parent = nodes[i]
        nodes[right_index].is_left = False

        nodes[i].left_re_encryption_key = f"re_key_L_{i}"
        nodes[i].right_re_encryption_key = f"re_key_R_{i}"

    return nodes[0]  # root

def export_keys_to_pem_files(root, folder="node_keys"):
    os.makedirs(folder, exist_ok=True)
    queue = [root]

    while queue:
        node = queue.pop(0)
        if node:
            identifier = node.data["identifier"].replace(" ", "_").replace("(", "").replace(")", "")

            # Save public key
            pub_path = os.path.join(folder, f"{identifier}_public.pem")
            with open(pub_path, "w") as f_pub:
                f_pub.write(node.data["encryption_key"])

            # Save private key
            priv_path = os.path.join(folder, f"{identifier}_private.pem")
            with open(priv_path, "w") as f_priv:
                f_priv.write(node.data["decryption_key"])

            queue.append(node.left)
            queue.append(node.right)

    print(f"[✓] All PEM keys saved to folder '{folder}'")

# Visualization helper
def visualize_tree(root):
    G = nx.DiGraph()
    pos = {}  # Positions for layout

    def add_edges(node, x=0, y=0, dx=1.0):
        if not node:
            return
        pos[node.data['identifier']] = (x, -y)
        if node.left:
            G.add_edge(node.data['identifier'], node.left.data['identifier'])
            add_edges(node.left, x - dx, y + 1, dx / 2)
        if node.right:
            G.add_edge(node.data['identifier'], node.right.data['identifier'])
            add_edges(node.right, x + dx, y + 1, dx / 2)

    add_edges(root)

    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, arrows=False, node_size=2000, node_color='skyblue', font_size=10)
    plt.title("Binary Tree Structure")
    plt.tight_layout()
    plt.savefig("binary_tree_visualization.png")  # Save to file
    plt.show()

# Tree printing and visualization
def print_tree(node, level=0):
    if node:
        indent = "   " * level
        print(f"{indent}- {node.data['identifier']} (is_left={node.is_left}, parent={node.parent.data['identifier'] if node.parent else 'None'})")
        print_tree(node.left, level + 1)
        print_tree(node.right, level + 1)

    if level == 0:  # Only call visualize_tree once after root is printed
        visualize_tree(node)

def rename_nodes_as_in_diagram(root):
    # Manual renaming based on BFS index
    name_map = {
        0: "0",
        1: "13", 2: "14",
        3: "9", 4: "10", 5: "11", 6: "12",
        7: "1 (U1)", 8: "2 (U2)", 9: "3 (U3)", 10: "4 (U4)",
        11: "5 (U5)", 12: "6 (U6)", 13: "7 (U7)", 14: "8 (U8)"
    }

    # BFS traversal to rename
    queue = [(root, 0)]
    while queue:
        node, idx = queue.pop(0)
        if node:
            node.data['identifier'] = name_map.get(idx, f"node_{idx}")
            queue.append((node.left, 2 * idx + 1))
            queue.append((node.right, 2 * idx + 2))

# Build and display tree
root = build_full_binary_tree(height=3)
rename_nodes_as_in_diagram(root)
print_tree(root)
export_keys_to_pem_files(root)