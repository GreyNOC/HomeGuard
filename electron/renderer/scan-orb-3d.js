/*
 * GreyNOC scan orb — Three.js WebGL indicator.
 *
 * Renders a neural-sentinel core inside the existing `.scan-orb` slot:
 *   - faceted icosahedron core with shifting emissive color
 *   - wireframe lattice shell with additive blending
 *   - multi-ring synapse particles, palette-tinted
 *   - occasional synapse flashes drawn as additive line segments
 *   - outer tracking ring (thin torus)
 *
 * State:
 *   - idle:   slow rotation, sparse firings, soft glow
 *   - active: faster rotation, frequent firings, bright glow
 *
 * Public API (returned from initScanOrb3D):
 *   { setActive(boolean), dispose() }
 */
(function () {
  "use strict";

  const PALETTE = {
    cyan: 0x7df1ff,
    blue: 0x4ea1ff,
    violet: 0xc66cff,
    gold: 0xffe769,
    green: 0x72ffbd,
    red: 0xff5470,
  };
  const PARTICLE_COLORS = [
    PALETTE.cyan,
    PALETTE.blue,
    PALETTE.violet,
    PALETTE.gold,
    PALETTE.green,
    PALETTE.cyan,
    PALETTE.violet,
  ];

  function hasWebGL() {
    try {
      const canvas = document.createElement("canvas");
      return !!(window.WebGLRenderingContext &&
        (canvas.getContext("webgl") || canvas.getContext("experimental-webgl")));
    } catch (err) {
      return false;
    }
  }

  function buildCore(THREE) {
    const geometry = new THREE.IcosahedronGeometry(0.78, 1);
    const material = new THREE.MeshStandardMaterial({
      color: 0x0a1320,
      emissive: 0x4ea1ff,
      emissiveIntensity: 0.85,
      metalness: 0.55,
      roughness: 0.32,
      flatShading: true,
    });
    return new THREE.Mesh(geometry, material);
  }

  function buildLattice(THREE) {
    const geometry = new THREE.IcosahedronGeometry(0.96, 1);
    const material = new THREE.MeshBasicMaterial({
      color: 0x7df1ff,
      wireframe: true,
      transparent: true,
      opacity: 0.55,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    return new THREE.Mesh(geometry, material);
  }

  function buildOuterRing(THREE) {
    const geometry = new THREE.TorusGeometry(1.32, 0.012, 6, 96);
    const material = new THREE.MeshBasicMaterial({
      color: 0x7df1ff,
      transparent: true,
      opacity: 0.42,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const ring = new THREE.Mesh(geometry, material);
    ring.rotation.x = Math.PI / 2;
    return ring;
  }

  function buildTrackingArcs(THREE) {
    const group = new THREE.Group();
    const arc = new THREE.TorusGeometry(1.42, 0.008, 4, 64, Math.PI * 0.42);
    const mat1 = new THREE.MeshBasicMaterial({
      color: 0xc66cff,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const mat2 = new THREE.MeshBasicMaterial({
      color: 0x72ffbd,
      transparent: true,
      opacity: 0.55,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const a = new THREE.Mesh(arc, mat1);
    a.rotation.set(Math.PI / 2, 0, 0.2);
    const b = new THREE.Mesh(arc, mat2);
    b.rotation.set(Math.PI / 2, 0, Math.PI + 0.7);
    group.add(a, b);
    return group;
  }

  function buildParticles(THREE) {
    const COUNT = 72;
    const positions = new Float32Array(COUNT * 3);
    const colors = new Float32Array(COUNT * 3);
    const orbits = new Array(COUNT);
    const color = new THREE.Color();

    for (let i = 0; i < COUNT; i++) {
      const ringIndex = i % 3;
      const radius = 1.08 + ringIndex * 0.16 + (Math.random() - 0.5) * 0.06;
      const tilt = (ringIndex - 1) * 0.55 + (Math.random() - 0.5) * 0.32;
      const yaw = Math.random() * Math.PI * 2;
      const speed = (0.18 + ringIndex * 0.06) * (ringIndex % 2 === 0 ? 1 : -1);
      const phase = Math.random() * Math.PI * 2;
      orbits[i] = { radius, tilt, yaw, speed, phase, ringIndex };

      const hex = PARTICLE_COLORS[i % PARTICLE_COLORS.length];
      color.setHex(hex);
      colors[i * 3 + 0] = color.r;
      colors[i * 3 + 1] = color.g;
      colors[i * 3 + 2] = color.b;
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
      size: 0.085,
      vertexColors: true,
      transparent: true,
      opacity: 0.95,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      sizeAttenuation: true,
    });

    const points = new THREE.Points(geometry, material);
    points.userData.orbits = orbits;
    points.userData.count = COUNT;
    return points;
  }

  function buildSynapseFlashes(THREE) {
    // Pool of reusable line segments rendered as a single LineSegments geometry.
    const MAX_FLASHES = 6;
    const positions = new Float32Array(MAX_FLASHES * 2 * 3);
    const colors = new Float32Array(MAX_FLASHES * 2 * 3);
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));

    const material = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      opacity: 0.0,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const lines = new THREE.LineSegments(geometry, material);
    lines.userData.flashes = []; // { startTime, duration, targetX, targetY, targetZ, color }
    lines.userData.max = MAX_FLASHES;
    return lines;
  }

  function init(host) {
    if (!host || host.dataset.scanOrb3d === "1") {
      return null;
    }
    if (!hasWebGL() || typeof window.THREE === "undefined") {
      return null;
    }
    const THREE = window.THREE;

    const canvas = document.createElement("canvas");
    canvas.className = "scan-orb-canvas";
    canvas.setAttribute("aria-hidden", "true");
    host.appendChild(canvas);
    host.classList.add("has-3d");
    host.dataset.scanOrb3d = "1";

    const renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      premultipliedAlpha: false,
      powerPreference: "high-performance",
    });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 50);
    camera.position.set(0, 0.18, 4.2);
    camera.lookAt(0, 0, 0);

    // Lights for the standard material on the core.
    const ambient = new THREE.AmbientLight(0x223044, 0.85);
    const keyLight = new THREE.DirectionalLight(0x7df1ff, 1.35);
    keyLight.position.set(2.5, 2.0, 3.2);
    const rimLight = new THREE.DirectionalLight(0xc66cff, 0.95);
    rimLight.position.set(-2.4, -1.6, -1.8);
    const fillLight = new THREE.PointLight(0x72ffbd, 0.55, 8);
    fillLight.position.set(0, 0, 2.8);
    scene.add(ambient, keyLight, rimLight, fillLight);

    const core = buildCore(THREE);
    const lattice = buildLattice(THREE);
    const ring = buildOuterRing(THREE);
    const arcs = buildTrackingArcs(THREE);
    const particles = buildParticles(THREE);
    const flashes = buildSynapseFlashes(THREE);

    const stage = new THREE.Group();
    stage.add(core, lattice, ring, arcs, particles, flashes);
    scene.add(stage);

    // Slight initial tilt for a more dimensional read.
    stage.rotation.x = -0.18;
    stage.rotation.z = 0.08;

    const state = {
      active: false,
      // Smooth interpolated intensity (0 = idle, 1 = active).
      intensity: 0,
      lastFlashAt: 0,
      time: 0,
      lastFrame: performance.now(),
      running: true,
      disposed: false,
    };

    const tmpColor = new THREE.Color();
    const tmpVec = new THREE.Vector3();

    function resize() {
      const rect = host.getBoundingClientRect();
      const w = Math.max(32, Math.round(rect.width));
      const h = Math.max(32, Math.round(rect.height));
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(host);

    function spawnFlash() {
      const userData = flashes.userData;
      if (userData.flashes.length >= userData.max) return;
      const orbits = particles.userData.orbits;
      const i = (Math.random() * orbits.length) | 0;
      const orbit = orbits[i];
      const t = state.time * orbit.speed + orbit.phase;
      const x = orbit.radius * Math.cos(t);
      const y = orbit.radius * Math.sin(orbit.tilt) * Math.sin(t);
      const z = orbit.radius * Math.cos(orbit.tilt) * Math.sin(t);
      const hex = PARTICLE_COLORS[i % PARTICLE_COLORS.length];
      userData.flashes.push({
        start: state.time,
        duration: 0.38 + Math.random() * 0.22,
        x,
        y,
        z,
        hex,
      });
    }

    function updateFlashes() {
      const userData = flashes.userData;
      const positions = flashes.geometry.attributes.position.array;
      const colors = flashes.geometry.attributes.color.array;
      let drawCount = 0;
      let peakOpacity = 0;

      userData.flashes = userData.flashes.filter(
        (f) => state.time - f.start < f.duration
      );

      for (let i = 0; i < userData.flashes.length; i++) {
        const f = userData.flashes[i];
        const k = (state.time - f.start) / f.duration;
        const fade = Math.sin(Math.PI * k); // 0 → 1 → 0 over duration
        peakOpacity = Math.max(peakOpacity, fade);

        // Start point at orbit position
        positions[i * 6 + 0] = f.x;
        positions[i * 6 + 1] = f.y;
        positions[i * 6 + 2] = f.z;
        // End at core center
        positions[i * 6 + 3] = 0;
        positions[i * 6 + 4] = 0;
        positions[i * 6 + 5] = 0;

        tmpColor.setHex(f.hex).multiplyScalar(0.7 + 0.6 * fade);
        for (let v = 0; v < 2; v++) {
          colors[i * 6 + v * 3 + 0] = tmpColor.r;
          colors[i * 6 + v * 3 + 1] = tmpColor.g;
          colors[i * 6 + v * 3 + 2] = tmpColor.b;
        }
        drawCount++;
      }

      flashes.geometry.setDrawRange(0, drawCount * 2);
      flashes.geometry.attributes.position.needsUpdate = true;
      flashes.geometry.attributes.color.needsUpdate = true;
      flashes.material.opacity = 0.6 * peakOpacity + 0.35 * peakOpacity * state.intensity;
    }

    function updateParticles(dt) {
      const positions = particles.geometry.attributes.position.array;
      const orbits = particles.userData.orbits;
      for (let i = 0; i < orbits.length; i++) {
        const o = orbits[i];
        const speedScale = 1 + state.intensity * 1.4;
        const t = state.time * o.speed * speedScale + o.phase;
        const cosT = Math.cos(t);
        const sinT = Math.sin(t);
        const sinTilt = Math.sin(o.tilt);
        const cosTilt = Math.cos(o.tilt);
        positions[i * 3 + 0] = o.radius * cosT;
        positions[i * 3 + 1] = o.radius * sinTilt * sinT;
        positions[i * 3 + 2] = o.radius * cosTilt * sinT;
      }
      particles.geometry.attributes.position.needsUpdate = true;
      particles.material.size = 0.075 + 0.04 * state.intensity;
      particles.material.opacity = 0.78 + 0.2 * state.intensity;
    }

    function updateCore(dt) {
      // Shift the core's emissive color through the palette over time.
      const hueT = state.time * 0.18;
      const r = 0.5 + 0.5 * Math.sin(hueT);
      const g = 0.5 + 0.5 * Math.sin(hueT + 2.1);
      const b = 0.5 + 0.5 * Math.sin(hueT + 4.2);
      core.material.emissive.setRGB(
        0.32 + 0.55 * r,
        0.55 + 0.4 * g,
        0.78 + 0.22 * b
      );
      core.material.emissiveIntensity = 0.7 + 0.35 * state.intensity + 0.12 * Math.sin(state.time * 2.3);

      // Subtle breathing scale on the core itself.
      const breathe = 1 + 0.045 * Math.sin(state.time * 1.7) + 0.04 * state.intensity;
      core.scale.setScalar(breathe);

      // Lattice opacity tracks intensity.
      lattice.material.opacity = 0.42 + 0.32 * state.intensity;
      lattice.rotation.x += dt * (0.22 + 0.5 * state.intensity);
      lattice.rotation.y -= dt * (0.32 + 0.6 * state.intensity);

      ring.rotation.z += dt * (0.18 + 0.35 * state.intensity);
      arcs.rotation.y += dt * (0.55 + 0.9 * state.intensity);
    }

    function frame(now) {
      if (state.disposed) return;
      const dt = Math.min(0.05, (now - state.lastFrame) / 1000);
      state.lastFrame = now;
      state.time += dt;

      // Smooth intensity toward target.
      const target = state.active ? 1 : 0;
      const easeRate = 2.4;
      state.intensity += (target - state.intensity) * Math.min(1, dt * easeRate);

      // Stage rotation — slow idle, faster when active.
      const rotSpeed = 0.22 + state.intensity * 0.6;
      stage.rotation.y += dt * rotSpeed;
      stage.rotation.x = -0.18 + Math.sin(state.time * 0.3) * 0.08;

      updateCore(dt);
      updateParticles(dt);

      // Synapse flash spawning — rate scales sharply with intensity.
      const flashRate = 0.6 + state.intensity * 4.4; // flashes per second
      if (state.time - state.lastFlashAt > 1 / flashRate) {
        spawnFlash();
        state.lastFlashAt = state.time;
      }
      updateFlashes();

      renderer.render(scene, camera);
      if (state.running) {
        requestAnimationFrame(frame);
      }
    }
    requestAnimationFrame(frame);

    function onVisibility() {
      if (document.hidden) {
        state.running = false;
      } else if (!state.running && !state.disposed) {
        state.running = true;
        state.lastFrame = performance.now();
        requestAnimationFrame(frame);
      }
    }
    document.addEventListener("visibilitychange", onVisibility);

    return {
      setActive(active) {
        state.active = Boolean(active);
      },
      dispose() {
        state.disposed = true;
        state.running = false;
        document.removeEventListener("visibilitychange", onVisibility);
        ro.disconnect();
        renderer.dispose();
        core.geometry.dispose();
        core.material.dispose();
        lattice.geometry.dispose();
        lattice.material.dispose();
        ring.geometry.dispose();
        ring.material.dispose();
        arcs.children.forEach((c) => {
          c.geometry.dispose();
          c.material.dispose();
        });
        particles.geometry.dispose();
        particles.material.dispose();
        flashes.geometry.dispose();
        flashes.material.dispose();
        if (canvas.parentNode === host) host.removeChild(canvas);
        host.classList.remove("has-3d");
        delete host.dataset.scanOrb3d;
      },
    };
  }

  window.initScanOrb3D = init;
})();
