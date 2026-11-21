import {useState} from 'react';
import {X} from 'lucide-react';
import {useForensicsStore} from '../store/useForensicsStore';
import type {AssetType, Severity} from '../types/forensics';

const CITY_PRESETS = [
  {label: 'Mumbai, India', country: 'India', code: 'IN', lat: 19.076, lon: 72.8777},
  {label: 'Bengaluru, India', country: 'India', code: 'IN', lat: 12.9716, lon: 77.5946},
  {label: 'Ashburn, VA, USA', country: 'United States', code: 'US', lat: 39.0438, lon: -77.4874},
  {label: 'Frankfurt, Germany', country: 'Germany', code: 'DE', lat: 50.1109, lon: 8.6821},
  {label: 'London, UK', country: 'United Kingdom', code: 'GB', lat: 51.5072, lon: -0.1276},
  {label: 'Singapore', country: 'Singapore', code: 'SG', lat: 1.3521, lon: 103.8198},
  {label: 'Tokyo, Japan', country: 'Japan', code: 'JP', lat: 35.6762, lon: 139.6503},
];

export function AddAssetModal() {
  const open = useForensicsStore((s) => s.addAssetModalOpen);
  const setOpen = useForensicsStore((s) => s.setAddAssetModalOpen);
  const createAsset = useForensicsStore((s) => s.createAsset);
  const flyTo = useForensicsStore((s) => s.flyTo);

  const [name, setName] = useState('');
  const [ipOrInternalId, setIpOrInternalId] = useState('');
  const [locationLabel, setLocationLabel] = useState('Bengaluru, India');
  const [country, setCountry] = useState('India');
  const [countryCode, setCountryCode] = useState('IN');
  const [latitude, setLatitude] = useState('12.9716');
  const [longitude, setLongitude] = useState('77.5946');
  const [assetType, setAssetType] = useState<AssetType>('api');
  const [criticality, setCriticality] = useState<Severity>('high');
  const [portsInput, setPortsInput] = useState('443, 8443');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!open) return null;

  const applyPreset = (idx: number) => {
    const p = CITY_PRESETS[idx];
    if (!p) return;
    setLocationLabel(p.label);
    setCountry(p.country);
    setCountryCode(p.code);
    setLatitude(String(p.lat));
    setLongitude(String(p.lon));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!name.trim() || !ipOrInternalId.trim() || !locationLabel.trim()) {
      setFormError('Asset name, IP/internal ID, and location are required.');
      return;
    }
    const lat = Number(latitude);
    const lon = Number(longitude);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) {
      setFormError('Enter valid latitude (-90 to 90) and longitude (-180 to 180).');
      return;
    }
    const openPorts = portsInput
      .split(',')
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);

    setSubmitting(true);
    const created = await createAsset({
      name: name.trim(),
      ipOrInternalId: ipOrInternalId.trim(),
      locationLabel: locationLabel.trim(),
      country,
      countryCode,
      latitude: lat,
      longitude: lon,
      assetType,
      criticality,
      openPorts: openPorts.length > 0 ? openPorts : [443],
    });
    setSubmitting(false);
    if (created) {
      flyTo(created.latitude, created.longitude, 2_500_000, created.name);
      setName('');
      setIpOrInternalId('');
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="add-asset-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
    >
      <div className="w-full max-w-lg border border-slate-700 bg-[#080E1C] text-slate-200 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3.5">
          <h2 id="add-asset-title" className="text-sm font-semibold text-white">
            Register Protected Target Asset
          </h2>
          <button
            type="button"
            onClick={() => setOpen(false)}
            aria-label="Close add asset modal"
            className="p-1 text-slate-400 hover:text-white"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3.5 p-5 text-xs">
          {formError && (
            <div className="border border-red-500/50 bg-red-500/10 px-3 py-2 text-red-300">
              {formError}
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="asset-name" className="block text-[11px] text-slate-400">
                Asset Name
              </label>
              <input
                id="asset-name"
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Bengaluru Core API"
                className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2.5 py-2 text-xs text-white focus:border-cyan-400 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="asset-ip" className="block text-[11px] text-slate-400">
                Public IP or Internal ID
              </label>
              <input
                id="asset-ip"
                type="text"
                required
                value={ipOrInternalId}
                onChange={(e) => setIpOrInternalId(e.target.value)}
                placeholder="e.g. 10.88.4.20 or SVC-API-09"
                className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2.5 py-2 font-mono text-xs text-white focus:border-cyan-400 focus:outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="asset-type" className="block text-[11px] text-slate-400">
                Asset Type
              </label>
              <select
                id="asset-type"
                value={assetType}
                onChange={(e) => setAssetType(e.target.value as AssetType)}
                className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2.5 py-2 text-xs text-white focus:border-cyan-400 focus:outline-none"
              >
                <option value="web_server">Web Server</option>
                <option value="database">Database</option>
                <option value="api">API Gateway</option>
                <option value="cloud_vm">Cloud VM</option>
                <option value="firewall">Firewall / VPN</option>
                <option value="email_server">Email Server</option>
                <option value="workstation">Workstation</option>
              </select>
            </div>
            <div>
              <label htmlFor="asset-criticality" className="block text-[11px] text-slate-400">
                Criticality Level
              </label>
              <select
                id="asset-criticality"
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as Severity)}
                className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2.5 py-2 text-xs text-white focus:border-cyan-400 focus:outline-none"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div>
            <span className="block text-[11px] text-slate-400">Quick Region Preset</span>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {CITY_PRESETS.map((p, idx) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => applyPreset(idx)}
                  className="border border-slate-800 bg-[#0B1221] px-2 py-1 text-[11px] text-slate-300 hover:border-cyan-400"
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2">
            <div className="col-span-3 sm:col-span-1">
              <label htmlFor="asset-loc" className="block text-[11px] text-slate-400">
                Location Label
              </label>
              <input
                id="asset-loc"
                type="text"
                required
                value={locationLabel}
                onChange={(e) => setLocationLabel(e.target.value)}
                className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2 py-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="asset-lat" className="block text-[11px] text-slate-400">
                Latitude
              </label>
              <input
                id="asset-lat"
                type="number"
                step="0.0001"
                required
                value={latitude}
                onChange={(e) => setLatitude(e.target.value)}
                className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2 py-1.5 font-mono text-xs text-white focus:border-cyan-400 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="asset-lon" className="block text-[11px] text-slate-400">
                Longitude
              </label>
              <input
                id="asset-lon"
                type="number"
                step="0.0001"
                required
                value={longitude}
                onChange={(e) => setLongitude(e.target.value)}
                className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2 py-1.5 font-mono text-xs text-white focus:border-cyan-400 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label htmlFor="asset-ports" className="block text-[11px] text-slate-400">
              Monitored Open Ports (comma-separated)
            </label>
            <input
              id="asset-ports"
              type="text"
              value={portsInput}
              onChange={(e) => setPortsInput(e.target.value)}
              placeholder="22, 443, 5432"
              className="mt-1 w-full border border-slate-700 bg-[#0B1221] px-2.5 py-2 font-mono text-xs text-white focus:border-cyan-400 focus:outline-none"
            />
          </div>

          <div className="flex justify-end gap-2 border-t border-slate-800 pt-3">
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="border border-slate-700 px-3.5 py-1.5 text-xs text-slate-300 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="bg-cyan-500 px-4 py-1.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50"
            >
              {submitting ? 'Registering…' : 'Register Asset'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
