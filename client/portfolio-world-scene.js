import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";

export const destinations = {
  about: { position: [-7, 2], arrival: [-7, 5], title: "About pavilion" },
  projects: { position: [7, 1], arrival: [7, 4], title: "Project workshop" },
  certifications: { position: [-5, -7], arrival: [-5, -3.5], title: "Credential gallery" },
  achievements: { position: [6, -7], arrival: [6, -3.5], title: "Milestone garden" },
  contact: { position: [1, 9], arrival: [1, 6.5], title: "Contact beacon" }
};

// All scenery is generated here. No downloaded models, trackers, or audio.
export function createWorld(host, { onOpen, onLocation, markers, onFailure }) {
  const scene = new THREE.Scene();
  scene.background = new THREE.Color("#f4d4ad");
  scene.fog = new THREE.Fog("#f4d4ad", 42, 105);
  const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFShadowMap;
  // Only the little data core/boat animate; the island's baked-looking shadows
  // can stay static instead of re-rendering hundreds of shadow casters each frame.
  renderer.shadowMap.autoUpdate = false;
  renderer.shadowMap.needsUpdate = true;
  renderer.domElement.setAttribute("aria-label", "Interactive portfolio island. Drag to rotate. Use the destination buttons to open exhibits.");
  renderer.domElement.tabIndex = 0;
  host.appendChild(renderer.domElement);
  const camera = new THREE.PerspectiveCamera(45, 1, .1, 180);
  camera.position.set(25, 22, 32);
  const controls = new OrbitControls(camera, renderer.domElement);
  controls.target.set(-3, 0, 0);
  controls.enableDamping = true;
  controls.enablePan = false;
  controls.minDistance = 19;
  controls.maxDistance = 52;
  controls.minPolarAngle = .25;
  controls.maxPolarAngle = Math.PI * .46;
  controls.rotateSpeed = .55;
  scene.add(new THREE.HemisphereLight("#fff4d9", "#789885", 2.5));
  const sun = new THREE.DirectionalLight("#ffe4b4", 3);
  sun.position.set(-15, 30, 12);
  sun.castShadow = true;
  sun.shadow.mapSize.set(1024, 1024);
  Object.assign(sun.shadow.camera, { left: -22, right: 22, top: 22, bottom: -22, near: 1, far: 70 });
  sun.shadow.normalBias = .06;
  scene.add(sun);

  const materials = new Map();
  const mat = (color, emissive = false) => {
    const key = `${color}:${emissive}`;
    if (!materials.has(key)) materials.set(key, new THREE.MeshStandardMaterial({ color, roughness: .9, flatShading: true, ...(emissive ? { emissive: color, emissiveIntensity: .5 } : {}) }));
    return materials.get(key);
  };
  const mesh = (geometry, color, parent, x = 0, y = 0, z = 0, emissive = false) => {
    const object = new THREE.Mesh(geometry, mat(color, emissive));
    object.position.set(x, y, z);
    object.castShadow = true;
    object.receiveShadow = true;
    parent.add(object);
    return object;
  };
  const box = (w, h, d, color, parent, x, y, z) => mesh(new THREE.BoxGeometry(w, h, d), color, parent, x, y, z);
  const cylinder = (r, h, color, parent, x, y, z, top = r, segments = 12) => mesh(new THREE.CylinderGeometry(top, r, h, segments), color, parent, x, y, z);
  const sphere = (r, color, parent, x, y, z, detail = 0) => mesh(new THREE.IcosahedronGeometry(r, detail), color, parent, x, y, z);
  const sea = mesh(new THREE.PlaneGeometry(250, 250), "#72bcb6", scene, 0, -1.5, 0);
  sea.rotation.x = -Math.PI / 2;
  sea.castShadow = false;
  cylinder(15.5, 1.5, "#e4c39b", scene, 0, -1.25, 0, 14.8, 64);
  cylinder(14.1, .85, "#8dac75", scene, 0, -.42, 0, 14.1, 64);
  cylinder(2.65, .12, "#ead5aa", scene, 0, .03, 0, 2.65, 32);

  // A ring of broken white water gives the shore a hand-placed, illustrated edge.
  const ripples = new THREE.Group();
  scene.add(ripples);
  for (let i = 0; i < 72; i++) {
    const angle = i * Math.PI * 2 / 72;
    const wave = box(.8 + (i % 3) * .3, .025, .08, "#c8e8d7", ripples, Math.cos(angle) * 16.2, -1.42, Math.sin(angle) * 16.2);
    wave.rotation.y = -angle - Math.PI / 2;
  }
  // Distant land, clouds, and a sun keep the horizon from feeling like a void.
  for (let i = 0; i < 14; i++) {
    const angle = i * Math.PI * 2 / 14;
    const mountain = mesh(new THREE.ConeGeometry(7 + i % 4, 6 + i % 3 * 2, 5), i % 2 ? "#b9c6ae" : "#a4c1b5", scene, Math.cos(angle) * 66, .5, Math.sin(angle) * 66);
    mountain.rotation.y = angle;
  }
  const sunlight = mesh(new THREE.SphereGeometry(5, 20, 16), "#fff2ce", scene, -43, 20, -48, true);
  sunlight.castShadow = false;
  const clouds = [];
  for (let i = 0; i < 8; i++) {
    const cloud = new THREE.Group();
    cloud.position.set(-38 + i * 11, 15 + i % 3 * 2, -35 - i % 2 * 12);
    for (let j = 0; j < 4; j++) {
      const puff = sphere(1.6, "#fff0d8", cloud, j * 1.7, Math.sin(j) * .4, 0, 1);
      puff.scale.set(1.5, .5, .7);
      puff.castShadow = false;
    }
    scene.add(cloud);
    clouds.push(cloud);
  }

  const colliders = [{ x: 0, z: -1.4, r: 2 }];
  const interactables = [];
  const animateObjects = [];
  const landmarkGroups = {};
  const labelAnchors = {};
  Object.entries(destinations).forEach(([id, destination]) => {
    const [x, z] = destination.position;
    const group = new THREE.Group();
    group.position.set(x, 0, z);
    group.userData.exhibit = id;
    scene.add(group);
    landmarkGroups[id] = group;
    labelAnchors[id] = new THREE.Vector3(x, id === "contact" ? 5 : 4.6, z);
    cylinder(2.3, .12, "#e6d2ad", group, 0, .06, 0, 2.3, 24);
    colliders.push({ x, z, r: id === "contact" ? .7 : 1.65 });
    const pathEnd = new THREE.Vector3(...[destination.arrival[0], .07, destination.arrival[1]]);
    for (let step = 1; step <= 12; step++) {
      const point = pathEnd.clone().multiplyScalar(step / 12);
      const stone = cylinder(.42, .04, step % 2 ? "#dfcda6" : "#efe0bc", scene, point.x, .045, point.z, .42, 7);
      stone.rotation.y = step * .6;
      stone.scale.z = .7;
    }
  });
  // The central observatory: terracotta roof, little windows, orbiting data core.
  const observatory = new THREE.Group();
  observatory.position.set(0, 0, -1.4);
  scene.add(observatory);
  cylinder(1.8, 3.4, "#f1dfba", observatory, 0, 1.7, 0, 1.6, 12);
  cylinder(1.9, .3, "#af6b47", observatory, 0, 3.4, 0, 1.9, 12);
  mesh(new THREE.ConeGeometry(2.2, 2.1, 12), "#c9744e", observatory, 0, 4.55, 0);
  for (let i = 0; i < 6; i++) {
    const a = i * Math.PI / 3;
    const windowPane = box(.5, .9, .08, "#416f6e", observatory, Math.sin(a) * 1.65, 2.1, Math.cos(a) * 1.65);
    windowPane.rotation.y = a;
  }
  box(.72, 1.5, .1, "#785240", observatory, 0, .75, 1.77);
  const core = new THREE.Group();
  core.position.set(0, 6.3, -1.4);
  scene.add(core);
  sphere(.55, "#77cfc2", core, 0, 0, 0, 1);
  for (let i = 0; i < 3; i++) {
    const orbit = mesh(new THREE.TorusGeometry(1.1, .045, 6, 48), "#d29950", core);
    orbit.rotation.set(i * .9, i * .8, i * .3);
  }
  animateObjects.push(core);

  const about = landmarkGroups.about;
  for (const x of [-1.4, 1.4]) for (const z of [-1, 1]) cylinder(.1, 2.6, "#9b7151", about, x, 1.4, z, .1, 8);
  const pavilionRoof = mesh(new THREE.ConeGeometry(2.5, 1.3, 4), "#597f68", about, 0, 3.15, 0);
  pavilionRoof.rotation.y = Math.PI / 4;
  box(2.6, .22, .6, "#a9764d", about, 0, .7, -.6);
  box(.8, 1.3, .08, "#fff0d0", about, 0, 1.5, -.85);
  // A small book and plant rather than generic glowing sci-fi panels.
  box(.65, .1, .45, "#427e81", about, .8, .89, -.55).rotation.y = .2;
  cylinder(.22, .4, "#bb774c", about, -1, 1, -.65, .29, 8);
  sphere(.38, "#688d54", about, -1, 1.48, -.65);

  const workshop = landmarkGroups.projects;
  box(3.1, 2.3, 2.3, "#efddb4", workshop, 0, 1.3, 0);
  const roof = mesh(new THREE.ConeGeometry(2.6, 1.5, 4), "#c07951", workshop, 0, 3.15, 0);
  roof.rotation.y = Math.PI / 4;
  box(2.2, 1.25, .12, "#2f6267", workshop, 0, 1.65, 1.22);
  for (let i = 0; i < 5; i++) box(.25 + i % 2 * .3, .06, .03, i % 2 ? "#e0c083" : "#83c8a9", workshop, -.6 + i % 2 * .8, 2.04 - i * .18, 1.3);
  box(1.5, .18, .6, "#a97951", workshop, 0, .8, 1.6);
  cylinder(.12, 2.2, "#a7794f", workshop, 1.65, 2.8, -.8, .12, 8);
  const antenna = mesh(new THREE.TorusGeometry(.65, .09, 6, 24), "#dba55e", workshop, 1.65, 4, -.8);
  antenna.rotation.y = .8;

  const gallery = landmarkGroups.certifications;
  const previewSlots = [];
  const previewTextures = new Set();
  const textureLoader = new THREE.TextureLoader();
  box(3.8, .16, 2, "#d3b68a", gallery, 0, .25, 0);
  for (let i = 0; i < 3; i++) {
    cylinder(.07, 2.3, "#a47650", gallery, (i - 1) * 1.25, 1.3, 0, .07, 8);
    box(1.15, 1.55, .16, "#ac7d45", gallery, (i - 1) * 1.25, 2.1, 0);
    box(.99, 1.39, .04, "#fff3d8", gallery, (i - 1) * 1.25, 2.1, .1);
    sphere(.18, "#cfaa62", gallery, (i - 1) * 1.25, 2.35, .16);
    for (let j = 0; j < 3; j++) box(.6, .025, .03, "#879787", gallery, (i - 1) * 1.25, 2 - j * .14, .135);
    const previewMaterial = new THREE.MeshBasicMaterial({ color: "#ffffff" });
    const preview = new THREE.Mesh(new THREE.PlaneGeometry(1, 1), previewMaterial);
    preview.position.set((i - 1) * 1.25, 2.1, .36);
    preview.visible = false;
    preview.userData.exhibit = "certifications";
    gallery.add(preview);
    previewSlots.push({ mesh: preview, material: previewMaterial, source: "", version: 0 });
  }
  const garden = landmarkGroups.achievements;
  for (let i = 0; i < 3; i++) {
    cylinder(.5, .5 + i * .65, "#d5bd91", garden, (i - 1) * 1.25, .3 + i * .325, 0, .5, 8);
    const gem = mesh(new THREE.OctahedronGeometry(.4), ["#76b6b0", "#d5a15b", "#c97753"][i], garden, (i - 1) * 1.25, .95 + i * .65, 0, true);
    animateObjects.push(gem);
  }
  const contact = landmarkGroups.contact;
  cylinder(.7, 3.3, "#efe0bb", contact, 0, 1.7, 0, .5, 8);
  cylinder(.85, .18, "#a1724f", contact, 0, 3.35, 0, .85, 8);
  cylinder(.4, .8, "#bde4c8", contact, 0, 3.85, 0, .4, 8);
  mesh(new THREE.ConeGeometry(.85, .75, 8), "#c47752", contact, 0, 4.6, 0);
  for (let i = 0; i < 9; i++) box(2, .16, .45, "#b58b61", scene, 1, -.25, 12.5 + i * .5);
  for (const x of [.2, 1.8]) for (const z of [12.5, 14.5, 16.5]) cylinder(.1, 1.4, "#927153", scene, x, -.65, z, .1, 7);
  const boat = new THREE.Group();
  boat.position.set(3.5, -1.1, 17);
  scene.add(boat);
  const hull = sphere(1, "#ab6e47", boat, 0, 0, 0, 1);
  hull.scale.set(.55, .3, 1.4);
  box(.8, .08, .25, "#e2c699", boat, 0, .2, 0);
  const sail = mesh(new THREE.ConeGeometry(.85, 1.7, 3), "#f5e8c8", boat, 0, 1.2, 0);
  sail.scale.z = .06;
  cylinder(.035, 2.3, "#826247", boat, 0, 1, 0, .035, 5);

  // Deterministic vegetation placement avoids layout changes on every visit.
  for (let i = 0; i < 32; i++) {
    const angle = i * 2.39996;
    const radius = 11.4 + (i % 3) * .6;
    const x = Math.cos(angle) * radius, z = Math.sin(angle) * radius;
    if (z > 9 && Math.abs(x - 1) < 3) continue;
    const tree = new THREE.Group();
    tree.position.set(x, 0, z);
    scene.add(tree);
    const height = 1.5 + i % 4 * .4;
    cylinder(.12, height, "#99744e", tree, 0, height / 2, 0, .1, 6);
    for (let j = 0; j < 3; j++) {
      const crown = sphere(.9 + i % 3 * .15, ["#65895b", "#809950", "#86a66f"][i % 3], tree, Math.cos(j * 2.1) * .4, height + j * .25, Math.sin(j * 2.1) * .4);
      crown.scale.y = .85;
    }
    const rock = sphere(.5, "#a8ad92", scene, x * 1.08, .12, z * 1.08);
    rock.scale.set(1.2, .65, .8);
  }
  for (let i = 0; i < 60; i++) {
    const a = i * 2.39996, r = 10 + i % 5 * .55;
    const stalk = cylinder(.025, .25, "#789052", scene, Math.cos(a) * r, .12, Math.sin(a) * r, .025, 4);
    sphere(.08, i % 2 ? "#edc58d" : "#e5d9b5", stalk, 0, .18, 0);
  }
  Object.values(landmarkGroups).forEach(group => {
    group.traverse(object => { if (object.isMesh) { object.userData.exhibit = group.userData.exhibit; interactables.push(object); } });
  });

  const keys = new Set();
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  const direction = new THREE.Vector3();
  const projected = new THREE.Vector3();
  const lookTarget = new THREE.Vector3();
  const motionPreference = window.matchMedia("(prefers-reduced-motion: reduce)");
  let reducedMotion = motionPreference.matches;
  let mode = "overview", blocked = true, yaw = 0, pitch = -.04;
  let dragging = null, disposed = false, frame = 0, lastTime = 0, elapsed = 0;
  let lastLocation = "", active = !document.hidden, flight = null, activeExhibit = null;
  const updateLook = () => {
    lookTarget.set(camera.position.x + Math.sin(yaw) * Math.cos(pitch), camera.position.y + Math.sin(pitch), camera.position.z - Math.cos(yaw) * Math.cos(pitch));
    camera.lookAt(lookTarget);
  };
  const overview = (intro = false) => {
    mode = "overview";
    controls.enabled = !blocked;
    controls.target.set(intro ? -3 : 0, 0, 0);
    camera.position.set(25, 22, 32);
    camera.lookAt(controls.target);
    flight = null;
    activeExhibit = null;
    keys.clear();
  };
  const walk = () => {
    mode = "walk";
    controls.enabled = false;
    camera.position.set(0, 1.9, 10);
    yaw = 0; pitch = -.04;
    flight = null;
    activeExhibit = null;
    keys.clear();
    updateLook();
  };
  const travel = id => {
    const destination = destinations[id];
    if (!destination) return;
    mode = "walk";
    controls.enabled = false;
    keys.clear();
    activeExhibit = id;
    const end = new THREE.Vector3(destination.arrival[0], 1.9, destination.arrival[1]);
    const endYaw = Math.atan2(destination.position[0] - end.x, end.z - destination.position[1]);
    if (reducedMotion) { camera.position.copy(end); yaw = endYaw; pitch = .06; updateLook(); }
    else flight = { start: camera.position.clone(), end, yawStart: yaw, yawEnd: endYaw, startedAt: performance.now(), time: 0 };
  };
  const hit = event => {
    const rect = renderer.domElement.getBoundingClientRect();
    pointer.set((event.clientX - rect.left) / rect.width * 2 - 1, -(event.clientY - rect.top) / rect.height * 2 + 1);
    raycaster.setFromCamera(pointer, camera);
    return raycaster.intersectObjects(interactables, false)[0]?.object.userData.exhibit;
  };
  const down = event => {
    if (blocked || event.button !== 0) return;
    renderer.domElement.focus({ preventScroll: true });
    dragging = { x: event.clientX, y: event.clientY, lastX: event.clientX, lastY: event.clientY, distance: 0, id: event.pointerId };
    renderer.domElement.setPointerCapture(event.pointerId);
  };
  const move = event => {
    if (blocked) return;
    if (dragging && event.pointerId === dragging.id) {
      const dx = event.clientX - dragging.lastX, dy = event.clientY - dragging.lastY;
      dragging.distance += Math.abs(dx) + Math.abs(dy);
      if (mode === "walk") {
        yaw -= dx * .004;
        pitch = THREE.MathUtils.clamp(pitch - dy * .004, -.65, .8);
        updateLook();
      }
      dragging.lastX = event.clientX; dragging.lastY = event.clientY;
    } else renderer.domElement.style.cursor = hit(event) ? "pointer" : mode === "walk" ? "crosshair" : "grab";
  };
  const up = event => {
    if (dragging && event.pointerId === dragging.id && dragging.distance < 7 && !blocked) {
      const exhibit = hit(event);
      if (exhibit) onOpen(exhibit);
    }
    dragging = null;
  };
  const keyDown = event => {
    if (blocked || mode !== "walk" || document.activeElement !== renderer.domElement) return;
    const key = event.key.toLowerCase();
    if (["w", "a", "s", "d", "arrowup", "arrowdown", "arrowleft", "arrowright", "q", "e"].includes(key)) { event.preventDefault(); keys.add(key); flight = null; activeExhibit = null; }
    if (key === "enter" && lastLocation) { event.preventDefault(); onOpen(lastLocation); }
  };
  const keyUp = event => keys.delete(event.key.toLowerCase());
  const clearKeys = () => { keys.clear(); dragging = null; };
  let viewportWidth = 1, viewportHeight = 1;
  const resize = () => {
    const { width, height } = host.getBoundingClientRect();
    viewportWidth = width; viewportHeight = height;
    renderer.setSize(width, height);
    camera.fov = width < 600 ? 75 : 45;
    camera.aspect = width / Math.max(height, 1);
    camera.updateProjectionMatrix();
  };
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(host);
  resize();
  const visibility = () => { active = !document.hidden; clearKeys(); lastTime = 0; };
  const motionChange = event => { reducedMotion = event.matches; controls.enableDamping = !reducedMotion; };
  const contextLost = event => { event.preventDefault(); onFailure(); };
  renderer.domElement.addEventListener("pointerdown", down);
  renderer.domElement.addEventListener("pointermove", move);
  renderer.domElement.addEventListener("pointerup", up);
  renderer.domElement.addEventListener("pointercancel", clearKeys);
  renderer.domElement.addEventListener("webglcontextlost", contextLost);
  window.addEventListener("keydown", keyDown);
  window.addEventListener("keyup", keyUp);
  window.addEventListener("blur", clearKeys);
  document.addEventListener("visibilitychange", visibility);
  motionPreference.addEventListener("change", motionChange);

  const tick = time => {
    if (disposed) return;
    frame = requestAnimationFrame(tick);
    if (!active) return;
    const dt = lastTime ? Math.min((time - lastTime) / 1000, .05) : 0;
    lastTime = time;
    elapsed += dt;
    if (!reducedMotion) {
      animateObjects.forEach((object, i) => { object.rotation.y += dt * .18; object.rotation.z = Math.sin(elapsed * .5 + i) * .09; });
      boat.rotation.z = Math.sin(elapsed * .7) * .035;
      boat.position.y = -1.1 + Math.sin(elapsed * .8) * .06;
      ripples.scale.setScalar(1 + Math.sin(elapsed * .5) * .012);
      clouds.forEach((cloud, i) => { cloud.position.x += dt * .02; if (cloud.position.x > 65) cloud.position.x = -65 - i; });
    }
    if (mode === "overview") controls.update();
    else if (!blocked) {
      if (flight) {
        flight.time = Math.min((time - flight.startedAt) / 1500, 1);
        const t = flight.time * flight.time * (3 - 2 * flight.time);
        camera.position.lerpVectors(flight.start, flight.end, t);
        camera.position.y += Math.sin(Math.PI * t) * 8;
        yaw = THREE.MathUtils.lerp(flight.yawStart, flight.yawEnd, t);
        pitch = .06;
        updateLook();
        if (flight.time === 1) flight = null;
      } else {
        const forward = Number(keys.has("w") || keys.has("arrowup")) - Number(keys.has("s") || keys.has("arrowdown"));
        const right = Number(keys.has("d") || keys.has("arrowright")) - Number(keys.has("a") || keys.has("arrowleft"));
        yaw += (Number(keys.has("q")) - Number(keys.has("e"))) * dt * 1.4;
        direction.set(Math.sin(yaw) * forward + Math.cos(yaw) * right, 0, -Math.cos(yaw) * forward + Math.sin(yaw) * right).normalize().multiplyScalar(dt * 3.2);
        const next = camera.position.clone().add(direction);
        const permitted = (x, z) => Math.hypot(x, z) < 13.5 && !colliders.some(c => Math.hypot(x - c.x, z - c.z) < c.r + .25);
        // Slide along structures instead of trapping the camera against an edge.
        if (permitted(next.x, camera.position.z)) camera.position.x = next.x;
        if (permitted(camera.position.x, next.z)) camera.position.z = next.z;
        updateLook();
      }
    }
    let nearby = "", distance = 5;
    Object.entries(destinations).forEach(([id, destination]) => {
      const d = Math.hypot(camera.position.x - destination.position[0], camera.position.z - destination.position[1]);
      if (d < distance && mode === "walk") { nearby = id; distance = d; }
      const marker = markers[id];
      if (!marker) return;
      projected.copy(labelAnchors[id]).project(camera);
      const visible = projected.z > -1 && projected.z < 1 && Math.abs(projected.x) < .92 && Math.abs(projected.y) < .8 && (!activeExhibit || mode === "overview");
      marker.hidden = !visible;
      if (visible) marker.style.transform = `translate(-50%, -100%) translate(${(projected.x + 1) * viewportWidth / 2}px, ${(-projected.y + 1) * viewportHeight / 2}px)`;
    });
    if (nearby !== lastLocation) { lastLocation = nearby; onLocation(nearby); }
    renderer.render(scene, camera);
  };
  frame = requestAnimationFrame(tick);
  return {
    setMode(next) { if (next === "walk") walk(); else overview(); },
    travel,
    setContent({ certifications }) {
      previewSlots.forEach((slot, index) => {
        const value = certifications[index]?.image_url;
        let source = "";
        try { if (value) { const parsed = new URL(value, window.location.origin); if (["http:", "https:"].includes(parsed.protocol)) source = parsed.href; } } catch { /* Keep the illustrated placeholder for invalid URLs. */ }
        if (slot.source === source) return;
        slot.source = source;
        const version = ++slot.version;
        slot.mesh.visible = false;
        if (slot.material.map) { previewTextures.delete(slot.material.map); slot.material.map.dispose(); slot.material.map = null; slot.material.needsUpdate = true; }
        if (!source) return;
        const texture = textureLoader.load(source, loaded => {
          if (disposed || slot.version !== version) { previewTextures.delete(loaded); loaded.dispose(); return; }
          loaded.colorSpace = THREE.SRGBColorSpace;
          const ratio = loaded.image.width / loaded.image.height;
          slot.mesh.scale.set(ratio > .98 / 1.35 ? .98 : 1.35 * ratio, ratio > .98 / 1.35 ? .98 / ratio : 1.35, 1);
          slot.material.map = loaded;
          slot.material.needsUpdate = true;
          slot.mesh.visible = true;
        }, undefined, () => { previewTextures.delete(texture); texture.dispose(); });
        previewTextures.add(texture);
      });
    },
    setBlocked(value) { blocked = value; controls.enabled = mode === "overview" && !value; clearKeys(); },
    move(key, pressed) { if (!blocked && mode === "walk") { flight = null; activeExhibit = null; if (pressed) keys.add(key); else keys.delete(key); } },
    focus() { renderer.domElement.focus({ preventScroll: true }); },
    dispose() {
      disposed = true;
      cancelAnimationFrame(frame);
      resizeObserver.disconnect(); controls.dispose();
      window.removeEventListener("keydown", keyDown); window.removeEventListener("keyup", keyUp); window.removeEventListener("blur", clearKeys);
      document.removeEventListener("visibilitychange", visibility); motionPreference.removeEventListener("change", motionChange);
      renderer.domElement.removeEventListener("pointerdown", down); renderer.domElement.removeEventListener("pointermove", move); renderer.domElement.removeEventListener("pointerup", up); renderer.domElement.removeEventListener("pointercancel", clearKeys); renderer.domElement.removeEventListener("webglcontextlost", contextLost);
      const geometries = new Set();
      scene.traverse(object => { if (object.geometry) geometries.add(object.geometry); });
      geometries.forEach(geometry => geometry.dispose()); materials.forEach(material => material.dispose());
      previewTextures.forEach(texture => texture.dispose()); previewSlots.forEach(slot => slot.material.dispose());
      renderer.dispose(); renderer.domElement.remove();
    }
  };
}
