import * as THREE from "three";

const CYAN = 0x9aeee3;
const AMBER = 0xf3bd78;

// Each study is built from geometry, with no model or texture downloads.
function network() {
  const group = new THREE.Group();
  const nodes = [];
  const count = 64;
  const geometry = new THREE.SphereGeometry(0.028, 8, 6);
  const material = new THREE.MeshBasicMaterial({ color: CYAN });
  const mesh = new THREE.InstancedMesh(geometry, material, count);
  const dummy = new THREE.Object3D();
  for (let index = 0; index < count; index += 1) {
    const y = 1 - (index / (count - 1)) * 2;
    const radius = Math.sqrt(1 - y * y);
    const angle = index * Math.PI * (3 - Math.sqrt(5));
    const point = new THREE.Vector3(Math.cos(angle) * radius, y, Math.sin(angle) * radius).multiplyScalar(1.5);
    nodes.push(point);
    dummy.position.copy(point);
    dummy.updateMatrix();
    mesh.setMatrixAt(index, dummy.matrix);
  }
  group.add(mesh);
  const connections = [];
  nodes.forEach((point, index) => {
    nodes.slice(index + 1).forEach((other) => {
      if (point.distanceTo(other) < 0.82) connections.push(point, other);
    });
  });
  group.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(connections), new THREE.LineBasicMaterial({ color: CYAN, transparent: true, opacity: 0.32 })));
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.53, 0), new THREE.MeshStandardMaterial({ color: 0x163d4e, emissive: 0x123442, metalness: 0.6, roughness: 0.3, flatShading: true }));
  const outline = new THREE.LineSegments(new THREE.EdgesGeometry(core.geometry), new THREE.LineBasicMaterial({ color: AMBER }));
  group.add(core, outline);
  return group;
}

function processor() {
  const group = new THREE.Group();
  group.rotation.set(0.6, 0.3, -0.3);
  const board = new THREE.Mesh(new THREE.BoxGeometry(2.7, 0.09, 2.7), new THREE.MeshStandardMaterial({ color: 0x163546, metalness: 0.6, roughness: 0.4 }));
  const chip = new THREE.Mesh(new THREE.BoxGeometry(0.98, 0.28, 0.98), new THREE.MeshStandardMaterial({ color: 0x324966, metalness: 0.8, roughness: 0.25 }));
  chip.position.y = 0.22;
  const lid = new THREE.Mesh(new THREE.BoxGeometry(0.66, 0.02, 0.66), new THREE.MeshStandardMaterial({ color: 0x90c9cf, metalness: 0.85, roughness: 0.3, emissive: 0x0d282c }));
  lid.position.y = 0.37;
  group.add(board, chip, lid);
  const pins = new THREE.InstancedMesh(new THREE.BoxGeometry(0.08, 0.06, 0.24), new THREE.MeshStandardMaterial({ color: AMBER, metalness: 0.6, roughness: 0.25 }), 32);
  const dummy = new THREE.Object3D();
  const traces = [];
  const leds = new THREE.InstancedMesh(new THREE.SphereGeometry(0.033, 8, 6), new THREE.MeshBasicMaterial({ color: CYAN }), 32);
  let index = 0;
  for (let side = 0; side < 4; side += 1) {
    for (let pin = 0; pin < 8; pin += 1) {
      const offset = (pin - 3.5) * 0.113;
      const angle = (side * Math.PI) / 2;
      const start = new THREE.Vector3(offset, 0.15, 0.57).applyAxisAngle(new THREE.Vector3(0, 1, 0), angle);
      dummy.position.copy(start);
      dummy.rotation.y = angle;
      dummy.updateMatrix();
      pins.setMatrixAt(index, dummy.matrix);
      const mid = new THREE.Vector3(offset, 0.065, 0.84).applyAxisAngle(new THREE.Vector3(0, 1, 0), angle);
      const end = new THREE.Vector3(offset * 2.5, 0.065, 1.18).applyAxisAngle(new THREE.Vector3(0, 1, 0), angle);
      traces.push(start, mid, mid, end);
      dummy.position.copy(end);
      dummy.updateMatrix();
      leds.setMatrixAt(index, dummy.matrix);
      index += 1;
    }
  }
  group.add(pins, leds, new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(traces), new THREE.LineBasicMaterial({ color: CYAN, transparent: true, opacity: 0.7 })));
  return group;
}

function dataCore() {
  const group = new THREE.Group();
  const core = new THREE.Mesh(new THREE.OctahedronGeometry(0.68), new THREE.MeshStandardMaterial({ color: AMBER, metalness: 0.72, roughness: 0.3, flatShading: true }));
  group.add(core);
  for (let index = 0; index < 3; index += 1) {
    const orbit = new THREE.Group();
    const radius = 1.15 + index * 0.23;
    orbit.rotation.set(index * 0.8 + 0.4, index * 1.1, index * 0.6);
    orbit.add(new THREE.Mesh(new THREE.TorusGeometry(radius, 0.015, 6, 96), new THREE.MeshBasicMaterial({ color: CYAN, transparent: true, opacity: 0.65 })));
    const packet = new THREE.Mesh(new THREE.BoxGeometry(0.12, 0.12, 0.12), new THREE.MeshBasicMaterial({ color: index === 1 ? AMBER : CYAN }));
    packet.position.x = radius;
    orbit.add(packet);
    group.add(orbit);
  }
  return group;
}

export function createTechnologyScene(mount, mode, preferences) {
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  renderer.setClearColor(0x000000, 0);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 30);
  camera.position.set(0, 0, 6.6);
  const rig = new THREE.Group();
  const artifact = mode === "processor" ? processor() : mode === "core" ? dataCore() : network();
  rig.add(artifact);
  scene.add(rig);
  scene.add(new THREE.HemisphereLight(0xb3ebf0, 0x15263d, 2.4));
  const key = new THREE.DirectionalLight(0xe1faff, 3.2);
  key.position.set(3, 4, 5);
  scene.add(key);
  const rim = new THREE.DirectionalLight(AMBER, 2);
  rim.position.set(-4, 1, -2);
  scene.add(rim);
  mount.appendChild(renderer.domElement);
  renderer.domElement.setAttribute("aria-hidden", "true");
  let disposed = false;
  let frame = 0;
  let inView = true;
  let lastFrame = 0;
  let rotation = 0;
  const pointer = { x: 0, y: 0 };
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const resize = () => {
    const width = Math.max(mount.clientWidth, 1);
    const height = Math.max(mount.clientHeight, 1);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height, false);
    renderer.render(scene, camera);
  };
  const draw = (time = 0) => {
    frame = 0;
    if (disposed || document.hidden || !inView) return;
    const elapsed = Math.min((time - lastFrame) / 1000, 0.05);
    if (time - lastFrame > 32 || !lastFrame) {
      lastFrame = time;
      if (!preferences.paused && !reducedMotion.matches) rotation += elapsed * 0.2;
      artifact.rotation.y = (mode === "processor" ? 0.3 : 0) + rotation;
      if (!reducedMotion.matches) {
        rig.rotation.x += (-pointer.y * 0.15 - rig.rotation.x) * 0.06;
        rig.rotation.y += (pointer.x * 0.24 - rig.rotation.y) * 0.06;
      }
      renderer.render(scene, camera);
    }
    if (!preferences.paused && !reducedMotion.matches) frame = requestAnimationFrame(draw);
  };
  const wake = () => {
    cancelAnimationFrame(frame);
    frame = 0;
    lastFrame = 0;
    draw(performance.now());
  };
  const move = (event) => {
    if (event.pointerType === "touch" || reducedMotion.matches || preferences.paused) return;
    const bounds = mount.getBoundingClientRect();
    pointer.x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 2;
    pointer.y = ((event.clientY - bounds.top) / bounds.height - 0.5) * 2;
  };
  const resetPointer = () => { pointer.x = 0; pointer.y = 0; };
  const observer = new ResizeObserver(resize);
  const visibility = new IntersectionObserver(([entry]) => { inView = entry.isIntersecting; wake(); });
  observer.observe(mount);
  visibility.observe(mount);
  mount.addEventListener("pointermove", move, { passive: true });
  mount.addEventListener("pointerleave", resetPointer);
  document.addEventListener("visibilitychange", wake);
  reducedMotion.addEventListener("change", wake);
  resize();
  wake();
  return {
    wake,
    dispose() {
      disposed = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      visibility.disconnect();
      mount.removeEventListener("pointermove", move);
      mount.removeEventListener("pointerleave", resetPointer);
      document.removeEventListener("visibilitychange", wake);
      reducedMotion.removeEventListener("change", wake);
      const geometries = new Set();
      const materials = new Set();
      scene.traverse((object) => {
        if (object.geometry) geometries.add(object.geometry);
        if (object.material) (Array.isArray(object.material) ? object.material : [object.material]).forEach((material) => materials.add(material));
        if (object.isInstancedMesh) object.dispose();
      });
      geometries.forEach((geometry) => geometry.dispose());
      materials.forEach((material) => material.dispose());
      renderer.dispose();
      renderer.domElement.remove();
    }
  };
}
