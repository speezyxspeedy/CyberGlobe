import {useEffect, useMemo, useRef, useState} from 'react';
import * as Cesium from 'cesium';
import 'cesium/Build/Cesium/Widgets/widgets.css';
import {
  formatCategoryLabel,
  selectFilteredEvents,
  severityHex,
  useForensicsStore,
} from '../store/useForensicsStore';
import type {GeoRiskEntry, ProtectedAsset, ThreatEvent} from '../types/forensics';

function detectSoftwareWebGL(): boolean {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
    if (!gl) return true;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return false;
    const renderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '');
    return /swiftshader|llvmpipe|software|mesa/i.test(renderer);
  } catch {
    return true;
  }
}

function buildArcPositions(
  srcLon: number,
  srcLat: number,
  dstLon: number,
  dstLat: number,
  steps = 36
): Cesium.Cartesian3[] {
  const start = Cesium.Cartographic.fromDegrees(srcLon, srcLat);
  const end = Cesium.Cartographic.fromDegrees(dstLon, dstLat);
  const geodesic = new Cesium.EllipsoidGeodesic(start, end);
  const distMeters = geodesic.surfaceDistance;
  const peakHeight = Math.min(2_600_000, Math.max(180_000, distMeters * 0.22));

  const positions: Cesium.Cartesian3[] = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const interp = geodesic.interpolateUsingFraction(t);
    const elevation = Math.sin(Math.PI * t) * peakHeight;
    positions.push(Cesium.Cartesian3.fromRadians(interp.longitude, interp.latitude, elevation));
  }
  return positions;
}

interface HoverInfo {
  x: number;
  y: number;
  title: string;
  subtitle: string;
  detail: string;
  severity?: string;
}

export function CyberGlobe() {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const viewerRef = useRef<Cesium.Viewer | null>(null);
  const arcCacheRef = useRef<Array<{entity: Cesium.Entity; positions: Cesium.Cartesian3[]; speed: number; phase: number}>>([]);
  const pulseCacheRef = useRef<Array<{entity: Cesium.Entity; baseRadius: number}>>([]);
  const [webglError, setWebglError] = useState<string | null>(null);
  const [hoverInfo, setHoverInfo] = useState<HoverInfo | null>(null);
  const [globeReady, setGlobeReady] = useState(false);

  const events = useForensicsStore((s) => s.events);
  const assets = useForensicsStore((s) => s.assets);
  const statistics = useForensicsStore((s) => s.statistics);
  const layers = useForensicsStore((s) => s.layers);
  const filters = useForensicsStore((s) => s.filters);
  const timelineMode = useForensicsStore((s) => s.timelineMode);
  const replayProgress = useForensicsStore((s) => s.replayProgress);
  const globeMode = useForensicsStore((s) => s.globeMode);
  const imageryMode = useForensicsStore((s) => s.imageryMode);
  const flyToTarget = useForensicsStore((s) => s.flyToTarget);
  const setSelectedEntity = useForensicsStore((s) => s.setSelectedEntity);
  const fetchIpIntelligence = useForensicsStore((s) => s.fetchIpIntelligence);

  const githubRepositories = useForensicsStore((s) => s.githubRepositories);
  const githubSecrets = useForensicsStore((s) => s.githubSecrets);
  const githubVulnerabilities = useForensicsStore((s) => s.githubVulnerabilities);
  const githubDeveloperActivities = useForensicsStore((s) => s.githubDeveloperActivities);

  const filteredEvents = useMemo(
    () => selectFilteredEvents(events, filters, layers, timelineMode, replayProgress),
    [events, filters, layers, timelineMode, replayProgress]
  );

  // Store latest callbacks in refs so Viewer mounts once
  const selectRef = useRef(setSelectedEntity);
  const fetchIpRef = useRef(fetchIpIntelligence);
  selectRef.current = setSelectedEntity;
  fetchIpRef.current = fetchIpIntelligence;

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const isSoftwareGl = detectSoftwareWebGL();
    let viewer: Cesium.Viewer | null = null;
    let animTimer: ReturnType<typeof setInterval> | null = null;
    let handler: Cesium.ScreenSpaceEventHandler | null = null;

    try {
      viewer = new Cesium.Viewer(container, {
        animation: false,
        baseLayerPicker: false,
        fullscreenButton: false,
        geocoder: false,
        homeButton: false,
        infoBox: false,
        sceneModePicker: false,
        selectionIndicator: false,
        timeline: false,
        navigationHelpButton: false,
        navigationInstructionsInitiallyVisible: false,
        shadows: false,
        shouldAnimate: false,
        requestRenderMode: isSoftwareGl,
        maximumRenderTimeChange: Infinity,
        baseLayer: false,
        skyBox: false,
        skyAtmosphere: new Cesium.SkyAtmosphere(),
        contextOptions: {
          webgl: {
            alpha: false,
            antialias: !isSoftwareGl,
            powerPreference: 'high-performance',
          },
        },
      });

      viewer.resolutionScale = isSoftwareGl ? 0.9 : Math.min(window.devicePixelRatio || 1, 1.75);
      viewer.scene.backgroundColor = Cesium.Color.fromCssColorString('#050811');
      viewer.scene.globe.baseColor = Cesium.Color.fromCssColorString('#071226');
      viewer.scene.globe.enableLighting = false;
      viewer.scene.globe.showGroundAtmosphere = true;
      viewer.scene.globe.atmosphereLightIntensity = 12.0;

      if (viewer.scene.sun) viewer.scene.sun.show = false;
      if (viewer.scene.moon) viewer.scene.moon.show = false;

      // Load local bundled NaturalEarthII tiled imagery so globe renders reliably with zero external dependency failures
      void Cesium.TileMapServiceImageryProvider.fromUrl(
        Cesium.buildModuleUrl('Assets/Textures/NaturalEarthII')
      ).then((provider) => {
        if (!viewer || viewer.isDestroyed()) return;
        const baseLayer = viewer.imageryLayers.addImageryProvider(provider);
        baseLayer.brightness = 0.48;
        baseLayer.contrast = 1.45;
        baseLayer.saturation = 0.5;
        baseLayer.gamma = 0.85;
        viewer.scene.requestRender();
      });

      // Set initial global command-center vantage point showing Europe, Middle East, India, and Asia-Pacific
      viewer.camera.setView({
        destination: Cesium.Cartesian3.fromDegrees(46.0, 26.0, 17_500_000),
      });

      // Handle WebGL context loss safely
      const canvas = viewer.scene.canvas;
      const onContextLost = (e: Event) => {
        e.preventDefault();
        setWebglError('WebGL rendering context paused. Restoring 3D globe…');
      };
      const onContextRestored = () => {
        setWebglError(null);
        viewer?.scene.requestRender();
      };
      canvas.addEventListener('webglcontextlost', onContextLost);
      canvas.addEventListener('webglcontextrestored', onContextRestored);

      // Entity picking (click & hover)
      handler = new Cesium.ScreenSpaceEventHandler(canvas);
      handler.setInputAction((movement: {position: Cesium.Cartesian2}) => {
        if (!viewer || viewer.isDestroyed()) return;
        const picked = viewer.scene.pick(movement.position);
        if (!Cesium.defined(picked) || !picked.id?.properties) return;
        const props = picked.id.properties;
        const kind = props.entityKind?.getValue(Cesium.JulianDate.now());
        if (kind === 'event') {
          const eventId = props.eventId?.getValue(Cesium.JulianDate.now());
          const sourceIp = props.sourceIp?.getValue(Cesium.JulianDate.now());
          if (eventId) {
            selectRef.current({kind: 'event', eventId});
            if (sourceIp) void fetchIpRef.current(sourceIp);
          }
        } else if (kind === 'asset') {
          const assetId = props.assetId?.getValue(Cesium.JulianDate.now());
          if (assetId) selectRef.current({kind: 'asset', assetId});
        } else if (kind === 'region') {
          const regionId = props.regionId?.getValue(Cesium.JulianDate.now());
          if (regionId) selectRef.current({kind: 'region', regionId});
        }
      }, Cesium.ScreenSpaceEventType.LEFT_CLICK);

      let lastMoveTs = 0;
      handler.setInputAction((movement: {endPosition: Cesium.Cartesian2}) => {
        const now = performance.now();
        if (now - lastMoveTs < 70) return;
        lastMoveTs = now;
        if (!viewer || viewer.isDestroyed()) return;
        const picked = viewer.scene.pick(movement.endPosition);
        if (Cesium.defined(picked) && picked.id?.properties) {
          const props = picked.id.properties;
          const title = props.hoverTitle?.getValue(Cesium.JulianDate.now());
          const subtitle = props.hoverSubtitle?.getValue(Cesium.JulianDate.now());
          const detail = props.hoverDetail?.getValue(Cesium.JulianDate.now());
          const severity = props.hoverSeverity?.getValue(Cesium.JulianDate.now());
          if (title) {
            canvas.style.cursor = 'pointer';
            setHoverInfo({
              x: movement.endPosition.x,
              y: movement.endPosition.y,
              title,
              subtitle: subtitle || '',
              detail: detail || '',
              severity,
            });
            return;
          }
        }
        canvas.style.cursor = 'grab';
        setHoverInfo(null);
      }, Cesium.ScreenSpaceEventType.MOUSE_MOVE);

      viewerRef.current = viewer;
      setGlobeReady(true);

      // Paced animation timer for moving data packets along attack arcs & pulsing critical markers
      let tick = 0;
      const frameMs = isSoftwareGl ? 180 : 45;
      animTimer = setInterval(() => {
        if (!viewer || viewer.isDestroyed()) return;
        tick += 1;
        const arcs = arcCacheRef.current;
        for (let i = 0; i < arcs.length; i++) {
          const item = arcs[i];
          const len = item.positions.length;
          if (len > 1) {
            const frac = ((tick * 0.025 * item.speed) + item.phase) % 1;
            const idx = Math.min(len - 1, Math.floor(frac * (len - 1)));
            item.entity.position = new Cesium.ConstantPositionProperty(item.positions[idx]);
          }
        }
        const pulses = pulseCacheRef.current;
        const pulseScale = 1 + 0.35 * Math.sin(tick * 0.28);
        for (let i = 0; i < pulses.length; i++) {
          const p = pulses[i];
          if (p.entity.ellipse) {
            const r = p.baseRadius * pulseScale;
            p.entity.ellipse.semiMajorAxis = new Cesium.ConstantProperty(r);
            p.entity.ellipse.semiMinorAxis = new Cesium.ConstantProperty(r);
          }
        }
        if (isSoftwareGl) {
          viewer.scene.requestRender();
        }
      }, frameMs);

      return () => {
        if (animTimer) clearInterval(animTimer);
        handler?.destroy();
        canvas.removeEventListener('webglcontextlost', onContextLost);
        canvas.removeEventListener('webglcontextrestored', onContextRestored);
        if (viewer && !viewer.isDestroyed()) {
          viewer.destroy();
        }
        viewerRef.current = null;
      };
    } catch (err) {
      setWebglError(err instanceof Error ? err.message : 'Unable to initialize 3D CesiumJS Globe');
    }
  }, []);

  // Switch 3D / 2D map projection cleanly
  useEffect(() => {
    const viewer = viewerRef.current;
    if (!viewer || viewer.isDestroyed()) return;
    if (globeMode === '2D') {
      viewer.scene.morphTo2D(0.6);
    } else {
      viewer.scene.morphTo3D(0.6);
    }
    viewer.scene.requestRender();
  }, [globeMode]);

  // Toggle optional CARTO Dark Matter imagery overlay on top of bundled NaturalEarthII
  useEffect(() => {
    const viewer = viewerRef.current;
    if (!viewer || viewer.isDestroyed()) return;
    while (viewer.imageryLayers.length > 1) {
      viewer.imageryLayers.remove(viewer.imageryLayers.get(viewer.imageryLayers.length - 1), true);
    }
    if (imageryMode === 'dark_carto') {
      const darkCarto = new Cesium.UrlTemplateImageryProvider({
        url: 'https://basemaps.cartocdn.com/dark_all/{z}/{x}/{y}@2x.png',
        maximumLevel: 16,
        credit: 'CARTO Dark Matter / OpenStreetMap',
      });
      const overlay = viewer.imageryLayers.addImageryProvider(darkCarto);
      overlay.alpha = 0.9;
    }
    viewer.scene.requestRender();
  }, [imageryMode]);

  // Camera fly-to handler
  useEffect(() => {
    const viewer = viewerRef.current;
    if (!viewer || viewer.isDestroyed() || !flyToTarget) return;
    viewer.camera.flyTo({
      destination: Cesium.Cartesian3.fromDegrees(
        flyToTarget.longitude,
        flyToTarget.latitude,
        flyToTarget.height ?? 3_600_000
      ),
      duration: 1.1,
    });
  }, [flyToTarget]);

  // Synchronize Cesium entities whenever filtered events, assets, layers, or heatmap data change
  useEffect(() => {
    const viewer = viewerRef.current;
    if (!viewer || viewer.isDestroyed() || !globeReady) return;

    viewer.entities.removeAll();
    const newArcPackets: Array<{entity: Cesium.Entity; positions: Cesium.Cartesian3[]; speed: number; phase: number}> = [];
    const newPulses: Array<{entity: Cesium.Entity; baseRadius: number}> = [];

    // 1. Global Threat Heatmap & Geographic Risk Matrix layers
    const geoMatrix: GeoRiskEntry[] = statistics?.geoRiskMatrix ?? [];
    if (layers.globalHeatmap || layers.geoRiskMatrix) {
      geoMatrix.forEach((region) => {
        const heatColor =
          region.avgRiskScore >= 85
            ? '#ef4444'
            : region.avgRiskScore >= 70
              ? '#f97316'
              : region.avgRiskScore >= 50
                ? '#f59e0b'
                : '#10b981';
        const radiusMeters = Math.max(240_000, Math.min(950_000, region.attackVolume * 180_000 + region.avgRiskScore * 3_500));

        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(region.longitude, region.latitude, 500),
          ellipse: {
            semiMajorAxis: radiusMeters,
            semiMinorAxis: radiusMeters,
            material: Cesium.Color.fromCssColorString(heatColor).withAlpha(layers.geoRiskMatrix ? 0.24 : 0.16),
            outline: layers.geoRiskMatrix,
            outlineColor: Cesium.Color.fromCssColorString(heatColor).withAlpha(0.7),
            outlineWidth: 1.5,
            height: 2_000,
          },
          label: layers.geoRiskMatrix
            ? {
                text: `${region.countryCode} · Risk ${region.avgRiskScore} (${region.attackVolume})`,
                font: '600 11px "JetBrains Mono", monospace',
                fillColor: Cesium.Color.WHITE,
                outlineColor: Cesium.Color.fromCssColorString('#050811'),
                outlineWidth: 3,
                style: Cesium.LabelStyle.FILL_AND_OUTLINE,
                pixelOffset: new Cesium.Cartesian2(0, -14),
                disableDepthTestDistance: Number.POSITIVE_INFINITY,
              }
            : undefined,
          properties: {
            entityKind: 'region',
            regionId: region.regionId,
            hoverTitle: `${region.country} (${region.topCity})`,
            hoverSubtitle: `Geographic Risk Matrix · Avg Risk ${region.avgRiskScore}/100`,
            detail: `${region.attackVolume} events · ${region.uniqueAttackerIps} unique IPs · ${region.blockedIps} blocked`,
            hoverDetail: `${region.attackVolume} events · ${region.uniqueAttackerIps} unique IPs · Trend: ${region.riskTrend}`,
            hoverSeverity: region.avgRiskScore >= 80 ? 'critical' : region.avgRiskScore >= 60 ? 'high' : 'medium',
          },
        });
      });
    }

    // 2. Target Protected Assets Layer
    if (layers.targetAssets) {
      assets.forEach((asset: ProtectedAsset) => {
        const assetColor = asset.criticality === 'critical' ? '#06b6d4' : '#38bdf8';
        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(asset.longitude, asset.latitude, 15_000),
          point: {
            pixelSize: asset.criticality === 'critical' ? 12 : 9,
            color: Cesium.Color.fromCssColorString(assetColor),
            outlineColor: Cesium.Color.fromCssColorString('#ecfeff'),
            outlineWidth: 2,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
          },
          label: {
            text: asset.name.split('(')[0].trim(),
            font: '600 11px "Plus Jakarta Sans", sans-serif',
            fillColor: Cesium.Color.fromCssColorString('#cffafe'),
            outlineColor: Cesium.Color.fromCssColorString('#050811'),
            outlineWidth: 3,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            pixelOffset: new Cesium.Cartesian2(0, 16),
            distanceDisplayCondition: new Cesium.DistanceDisplayCondition(0, 14_000_000),
          },
          properties: {
            entityKind: 'asset',
            assetId: asset.id,
            hoverTitle: asset.name,
            hoverSubtitle: `Protected Asset (${asset.assetType.replace('_', ' ')}) · ${asset.locationLabel}`,
            hoverDetail: `Criticality: ${asset.criticality.toUpperCase()} · Risk ${asset.riskScore}/100 · Open ports: ${asset.openPorts.join(', ')}`,
            hoverSeverity: asset.criticality,
          },
        });
      });
    }

    // 3. Attack Sources, Uncertainty Radius Circles, VPN/Tor Rings, Reputation Halos, and Animated Attack Arcs
    const seenSourceIps = new Set<string>();
    filteredEvents.forEach((ev: ThreatEvent, idx: number) => {
      const colorHex = severityHex(ev.severity);
      const cesiumColor = Cesium.Color.fromCssColorString(colorHex);

      // Attack Source Marker + Uncertainty Radius Ellipse
      if (layers.attackSources && !seenSourceIps.has(ev.sourceIp)) {
        seenSourceIps.add(ev.sourceIp);
        const radiusMeters = Math.max(45_000, ev.sourceLocation.accuracyRadiusKm * 1_600);

        // Mandatory approximate-location confidence radius ring
        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(ev.sourceLocation.longitude, ev.sourceLocation.latitude, 1_500),
          ellipse: {
            semiMajorAxis: radiusMeters,
            semiMinorAxis: radiusMeters,
            material: cesiumColor.withAlpha(0.14),
            outline: true,
            outlineColor: cesiumColor.withAlpha(0.65),
            outlineWidth: 1.5,
            height: 1_500,
          },
          properties: {
            entityKind: 'event',
            eventId: ev.id,
            sourceIp: ev.sourceIp,
            hoverTitle: `${ev.sourceIp} (${ev.sourceLocation.city}, ${ev.sourceLocation.country})`,
            hoverSubtitle: `Approx. network location (±${ev.sourceLocation.accuracyRadiusKm} km confidence radius)`,
            hoverDetail: `${ev.asn} · ${ev.isp} · Risk ${ev.riskScore}/100 (${ev.severity.toUpperCase()})`,
            hoverSeverity: ev.severity,
          },
        });

        // Pulsing halo for critical threats
        if (ev.severity === 'critical') {
          const pulseEntity = viewer.entities.add({
            position: Cesium.Cartesian3.fromDegrees(ev.sourceLocation.longitude, ev.sourceLocation.latitude, 3_000),
            ellipse: {
              semiMajorAxis: radiusMeters * 1.4,
              semiMinorAxis: radiusMeters * 1.4,
              material: Cesium.Color.fromCssColorString('#ef4444').withAlpha(0.08),
              outline: true,
              outlineColor: Cesium.Color.fromCssColorString('#ef4444').withAlpha(0.85),
              outlineWidth: 2,
              height: 3_000,
            },
          });
          newPulses.push({entity: pulseEntity, baseRadius: radiusMeters * 1.35});
        }

        // VPN / Proxy / Tor exposure outer marker ring
        if (layers.vpnProxyTor && (ev.connectionType === 'vpn' || ev.connectionType === 'proxy' || ev.connectionType === 'tor')) {
          viewer.entities.add({
            position: Cesium.Cartesian3.fromDegrees(ev.sourceLocation.longitude, ev.sourceLocation.latitude, 2_500),
            ellipse: {
              semiMajorAxis: radiusMeters * 1.85,
              semiMinorAxis: radiusMeters * 1.85,
              material: Cesium.Color.fromCssColorString('#a855f7').withAlpha(0.06),
              outline: true,
              outlineColor: Cesium.Color.fromCssColorString('#c084fc').withAlpha(0.8),
              outlineWidth: 1.5,
              height: 2_500,
            },
          });
        }

        // Threat Reputation halo ring
        if (layers.threatReputation && ev.abuseConfidence >= 70) {
          viewer.entities.add({
            position: Cesium.Cartesian3.fromDegrees(ev.sourceLocation.longitude, ev.sourceLocation.latitude, 2_000),
            ellipse: {
              semiMajorAxis: radiusMeters * 2.1,
              semiMinorAxis: radiusMeters * 2.1,
              material: Cesium.Color.fromCssColorString('#f97316').withAlpha(0.05),
              outline: true,
              outlineColor: Cesium.Color.fromCssColorString('#fb923c').withAlpha(0.75),
              outlineWidth: 1.2,
              height: 2_000,
            },
          });
        }

        // Core suspicious IP point marker
        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(ev.sourceLocation.longitude, ev.sourceLocation.latitude, 20_000),
          point: {
            pixelSize: ev.severity === 'critical' ? 11 : ev.severity === 'high' ? 9 : 7,
            color: cesiumColor,
            outlineColor: Cesium.Color.fromCssColorString('#050811'),
            outlineWidth: 2,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
          },
          properties: {
            entityKind: 'event',
            eventId: ev.id,
            sourceIp: ev.sourceIp,
            hoverTitle: `${ev.sourceIp} — ${formatCategoryLabel(ev.eventType)}`,
            hoverSubtitle: `Approx. ${ev.sourceLocation.city}, ${ev.sourceLocation.country} (±${ev.sourceLocation.accuracyRadiusKm} km)`,
            hoverDetail: `Risk ${ev.riskScore}/100 · Abuse ${ev.abuseConfidence}% · ${ev.connectionType.toUpperCase()}`,
            hoverSeverity: ev.severity,
          },
        });
      }

      // 4. Animated Geodesic 3D Attack Arcs + Moving Data Packets
      if (layers.attackArcs) {
        const arcPositions = buildArcPositions(
          ev.sourceLocation.longitude,
          ev.sourceLocation.latitude,
          ev.destinationLocation.longitude,
          ev.destinationLocation.latitude,
          34
        );
        const volumeBoost =
          (ev.metadata.attempts && ev.metadata.attempts > 250) ||
          (ev.metadata.bytesTransferred && ev.metadata.bytesTransferred > 100_000_000)
            ? 3.4
            : ev.severity === 'critical'
              ? 2.8
              : 1.9;

        viewer.entities.add({
          polyline: {
            positions: arcPositions,
            width: volumeBoost,
            material: new Cesium.PolylineGlowMaterialProperty({
              glowPower: 0.24,
              color: cesiumColor.withAlpha(0.88),
            }),
          },
          properties: {
            entityKind: 'event',
            eventId: ev.id,
            sourceIp: ev.sourceIp,
            hoverTitle: `${formatCategoryLabel(ev.eventType)} · ${ev.severity.toUpperCase()}`,
            hoverSubtitle: `${ev.sourceIp} (${ev.sourceLocation.city}) → ${ev.targetAssetName}`,
            hoverDetail: `Risk ${ev.riskScore}/100 · ${ev.protocol}:${ev.destinationPort} · Confidence ${ev.confidence}%`,
            hoverSeverity: ev.severity,
          },
        });

        // Moving packet entity along the geodesic arc
        const packetEntity = viewer.entities.add({
          position: arcPositions[0],
          point: {
            pixelSize: ev.severity === 'critical' ? 6.5 : 5,
            color: Cesium.Color.WHITE,
            outlineColor: cesiumColor,
            outlineWidth: 2,
          },
        });
        newArcPackets.push({
          entity: packetEntity,
          positions: arcPositions,
          speed: ev.severity === 'critical' ? 1.45 : ev.severity === 'high' ? 1.15 : 0.85,
          phase: (idx * 0.19) % 1,
        });
      }
    });

    // 5. GitHub CodeSec Vault Repositories Layer
    if (layers.githubRepos && githubRepositories.length > 0) {
      githubRepositories.forEach((repo) => {
        if (!repo.locationCoordinates) return;
        const isCritical = repo.riskScore >= 80;
        const isHigh = repo.riskScore >= 60;
        const repoColor = isCritical ? '#ef4444' : isHigh ? '#f97316' : '#38bdf8';
        const cesiumRepoColor = Cesium.Color.fromCssColorString(repoColor);

        // Vault Outline Ellipse
        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(
            repo.locationCoordinates.longitude,
            repo.locationCoordinates.latitude,
            5_000
          ),
          ellipse: {
            semiMajorAxis: 260_000,
            semiMinorAxis: 260_000,
            material: cesiumRepoColor.withAlpha(0.12),
            outline: true,
            outlineColor: cesiumRepoColor.withAlpha(0.85),
            outlineWidth: isCritical ? 2.5 : 1.5,
            height: 5_000,
          },
          properties: {
            entityKind: 'github_repo',
            hoverTitle: `Vault: ${repo.name}`,
            hoverSubtitle: `Repository Risk ${repo.riskScore}/100 (${repo.riskLevel.toUpperCase()}) · ${repo.language}`,
            hoverDetail: `Branch Protection: ${repo.branchProtection?.enabled ? 'Active' : 'Disabled'} · Secrets: ${repo.exposedSecretCount} · CVEs: ${repo.vulnerabilityCount?.critical || 0} crit`,
            hoverSeverity: repo.riskLevel,
          },
        });

        // Core Vault marker point
        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(
            repo.locationCoordinates.longitude,
            repo.locationCoordinates.latitude,
            24_000
          ),
          point: {
            pixelSize: isCritical ? 13 : 10,
            color: cesiumRepoColor,
            outlineColor: Cesium.Color.fromCssColorString('#ffffff'),
            outlineWidth: 2,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
          },
          label: {
            text: `[Vault] ${repo.name} · ${repo.riskScore}`,
            font: '600 11px "JetBrains Mono", monospace',
            fillColor: Cesium.Color.fromCssColorString('#e2e8f0'),
            outlineColor: Cesium.Color.fromCssColorString('#050811'),
            outlineWidth: 3,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            pixelOffset: new Cesium.Cartesian2(0, 18),
            distanceDisplayCondition: new Cesium.DistanceDisplayCondition(0, 16_000_000),
          },
          properties: {
            entityKind: 'github_repo',
            hoverTitle: `Vault: ${repo.name}`,
            hoverSubtitle: `Repository Risk ${repo.riskScore}/100 (${repo.riskLevel.toUpperCase()}) · ${repo.language}`,
            hoverDetail: `Branch Protection: ${repo.branchProtection?.enabled ? 'Active' : 'Disabled'} · Secrets: ${repo.exposedSecretCount} · CVEs: ${repo.vulnerabilityCount?.critical || 0} crit`,
            hoverSeverity: repo.riskLevel,
          },
        });

        // CI/CD Animated Workflow Arcs: Connect repo to linked cloud asset
        if (repo.linkedAssetId) {
          const linkedAsset = assets.find((a) => a.id === repo.linkedAssetId);
          if (linkedAsset) {
            const pipelineArcPositions = buildArcPositions(
              repo.locationCoordinates.longitude,
              repo.locationCoordinates.latitude,
              linkedAsset.longitude,
              linkedAsset.latitude,
              30
            );

            viewer.entities.add({
              polyline: {
                positions: pipelineArcPositions,
                width: 2.2,
                material: new Cesium.PolylineGlowMaterialProperty({
                  glowPower: 0.2,
                  color: Cesium.Color.fromCssColorString('#38bdf8').withAlpha(0.85),
                }),
              },
              properties: {
                entityKind: 'ci_cd_arc',
                hoverTitle: `CI/CD Pipeline: ${repo.name} → ${linkedAsset.name}`,
                hoverSubtitle: `Automated Deployment Pipeline · Blast Radius: ${repo.blastRadiusScore}/100`,
                hoverDetail: `Deployed to ${linkedAsset.locationLabel} (${linkedAsset.criticality.toUpperCase()})`,
                hoverSeverity: 'medium',
              },
            });
          }
        }
      });
    }

    // 6. Exposed Secrets Layer (Red Alert Markers)
    if (layers.exposedSecrets && githubSecrets.length > 0) {
      githubSecrets.forEach((sec) => {
        const repo = githubRepositories.find((r) => r.id === sec.repositoryId || r.name === sec.repositoryName);
        if (!repo?.locationCoordinates) return;

        const secLon = repo.locationCoordinates.longitude + 0.35;
        const secLat = repo.locationCoordinates.latitude + 0.25;

        const alertPulse = viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(secLon, secLat, 10_000),
          ellipse: {
            semiMajorAxis: 180_000,
            semiMinorAxis: 180_000,
            material: Cesium.Color.fromCssColorString('#ef4444').withAlpha(0.18),
            outline: true,
            outlineColor: Cesium.Color.fromCssColorString('#ef4444').withAlpha(0.95),
            outlineWidth: 2,
            height: 10_000,
          },
          properties: {
            entityKind: 'github_secret',
            hoverTitle: `🚨 LEAKED SECRET: ${sec.secretTypeLabel}`,
            hoverSubtitle: `Masked Fingerprint: ${sec.maskedFingerprint} (${sec.exposureRisk.toUpperCase()})`,
            hoverDetail: `${sec.repositoryName} → ${sec.filePath}:${sec.line} · Commit ${sec.commitSha.slice(0, 7)} by ${sec.commitAuthor}`,
            hoverSeverity: 'critical',
          },
        });
        newPulses.push({ entity: alertPulse, baseRadius: 180_000 });

        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(secLon, secLat, 28_000),
          point: {
            pixelSize: 12,
            color: Cesium.Color.fromCssColorString('#ef4444'),
            outlineColor: Cesium.Color.WHITE,
            outlineWidth: 2,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
          },
          label: {
            text: `🚨 ${sec.maskedFingerprint}`,
            font: '700 11px "JetBrains Mono", monospace',
            fillColor: Cesium.Color.fromCssColorString('#fca5a5'),
            outlineColor: Cesium.Color.fromCssColorString('#450a0a'),
            outlineWidth: 3,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            pixelOffset: new Cesium.Cartesian2(0, -16),
            distanceDisplayCondition: new Cesium.DistanceDisplayCondition(0, 14_000_000),
          },
          properties: {
            entityKind: 'github_secret',
            hoverTitle: `🚨 LEAKED SECRET: ${sec.secretTypeLabel}`,
            hoverSubtitle: `Masked Fingerprint: ${sec.maskedFingerprint} (${sec.exposureRisk.toUpperCase()})`,
            hoverDetail: `${sec.repositoryName} → ${sec.filePath}:${sec.line} · Remediation: ${sec.remediationPlan[0]}`,
            hoverSeverity: 'critical',
          },
        });
      });
    }

    // 7. Supply-Chain Vulnerabilities Layer (Orange Markers)
    if (layers.supplyChain && githubVulnerabilities.length > 0) {
      githubVulnerabilities.forEach((vuln) => {
        const repo = githubRepositories.find((r) => r.id === vuln.repositoryId || r.name === vuln.repositoryName);
        if (!repo?.locationCoordinates) return;

        const vLon = repo.locationCoordinates.longitude - 0.35;
        const vLat = repo.locationCoordinates.latitude - 0.25;

        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(vLon, vLat, 22_000),
          point: {
            pixelSize: 9,
            color: Cesium.Color.fromCssColorString('#f97316'),
            outlineColor: Cesium.Color.fromCssColorString('#ffedd5'),
            outlineWidth: 1.5,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
          },
          label: {
            text: `📦 ${vuln.cveId} (${vuln.packageName})`,
            font: '600 10px "JetBrains Mono", monospace',
            fillColor: Cesium.Color.fromCssColorString('#fed7aa'),
            outlineColor: Cesium.Color.fromCssColorString('#431407'),
            outlineWidth: 3,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            pixelOffset: new Cesium.Cartesian2(0, 16),
            distanceDisplayCondition: new Cesium.DistanceDisplayCondition(0, 12_000_000),
          },
          properties: {
            entityKind: 'github_vuln',
            hoverTitle: `${vuln.cveId}: ${vuln.packageName} v${vuln.currentVersion}`,
            hoverSubtitle: `Vulnerable Dependency · Fix: v${vuln.fixedVersion || 'N/A'} · ${vuln.severity.toUpperCase()}`,
            hoverDetail: `${vuln.summary} (${vuln.manifestPath})`,
            hoverSeverity: vuln.severity,
          },
        });
      });
    }

    // 8. Developer Anomalies Layer (Yellow Markers)
    if (layers.developerActivity && githubDeveloperActivities.length > 0) {
      githubDeveloperActivities.forEach((dev) => {
        if (!dev.location) return;

        viewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(dev.location.longitude, dev.location.latitude, 25_000),
          point: {
            pixelSize: 11,
            color: Cesium.Color.fromCssColorString('#eab308'),
            outlineColor: Cesium.Color.WHITE,
            outlineWidth: 2,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
          },
          label: {
            text: `👤 ${dev.actor || dev.username} (${dev.isOffHours ? 'Off-Hours' : 'Anomaly'})`,
            font: '600 10px "JetBrains Mono", monospace',
            fillColor: Cesium.Color.fromCssColorString('#fef08a'),
            outlineColor: Cesium.Color.fromCssColorString('#422006'),
            outlineWidth: 3,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            pixelOffset: new Cesium.Cartesian2(0, -16),
            distanceDisplayCondition: new Cesium.DistanceDisplayCondition(0, 14_000_000),
          },
          properties: {
            entityKind: 'github_dev',
            hoverTitle: `Developer Anomaly: ${dev.actor || dev.username}`,
            hoverSubtitle: `${dev.anomalyReason} · Score ${dev.anomalyScore}/100`,
            hoverDetail: `Modified: ${dev.filesChanged.join(', ')} · IP: ${dev.ipAddress || 'Internal'} (${dev.location.city})`,
            hoverSeverity: dev.anomalyScore >= 75 ? 'critical' : 'high',
          },
        });
      });
    }

    // 9. Simulated Attack Arc from Suspicious IP to Compromised Repository
    // (Amsterdam 52.3676, 4.9041 -> Ashburn infra-cloud-terraform 39.0438, -77.4874)
    if (layers.attackArcs) {
      const amsToAshburnArc = buildArcPositions(4.9041, 52.3676, -77.4874, 39.0438, 36);
      viewer.entities.add({
        polyline: {
          positions: amsToAshburnArc,
          width: 3.2,
          material: new Cesium.PolylineGlowMaterialProperty({
            glowPower: 0.3,
            color: Cesium.Color.fromCssColorString('#ef4444').withAlpha(0.95),
          }),
        },
        properties: {
          entityKind: 'attack_arc',
          hoverTitle: 'Simulated Attack Arc: Credential Access to infra-cloud-terraform',
          hoverSubtitle: '198.51.100.204 (Amsterdam VPN) → infra-cloud-terraform (Ashburn)',
          hoverDetail: 'Exploitation of leaked AWS IAM Access Key AKIA••••••••••••7X9A',
          hoverSeverity: 'critical',
        },
      });

      const attackPacket = viewer.entities.add({
        position: amsToAshburnArc[0],
        point: {
          pixelSize: 7,
          color: Cesium.Color.WHITE,
          outlineColor: Cesium.Color.fromCssColorString('#ef4444'),
          outlineWidth: 2,
        },
      });
      newArcPackets.push({
        entity: attackPacket,
        positions: amsToAshburnArc,
        speed: 1.6,
        phase: 0.45,
      });
    }

    arcCacheRef.current = newArcPackets;
    pulseCacheRef.current = newPulses;
    viewer.scene.requestRender();
  }, [filteredEvents, assets, statistics, layers, globeReady, githubRepositories, githubSecrets, githubVulnerabilities, githubDeveloperActivities]);

  if (webglError) {
    return (
      <div className="flex h-full w-full items-center justify-center bg-[#050811] text-slate-300">
        <div className="max-w-md border border-slate-800 bg-[#0B1221] p-6 text-center">
          <h2 className="text-base font-semibold text-white">3D Globe Renderer Unavailable</h2>
          <p className="mt-2 text-xs text-slate-400">{webglError}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative h-full w-full bg-[#050811]" data-testid="cesium-globe-container">
      <div ref={containerRef} className="h-full w-full" />

      {/* Subtle hover readout anchored near picked globe entity */}
      {hoverInfo && (
        <div
          className="pointer-events-none fixed z-40 max-w-xs border border-slate-700/90 bg-[#070B14]/95 px-3 py-2 shadow-xl"
          style={{
            left: Math.min(window.innerWidth - 300, hoverInfo.x + 14),
            top: Math.max(64, hoverInfo.y - 12),
          }}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-white">{hoverInfo.title}</span>
            {hoverInfo.severity && (
              <span
                className="font-mono text-[10px] font-semibold uppercase"
                style={{color: severityHex(hoverInfo.severity as 'low' | 'medium' | 'high' | 'critical')}}
              >
                {hoverInfo.severity}
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[11px] text-cyan-300">{hoverInfo.subtitle}</p>
          <p className="mt-0.5 font-mono text-[10px] text-slate-400">{hoverInfo.detail}</p>
        </div>
      )}
    </div>
  );
}
