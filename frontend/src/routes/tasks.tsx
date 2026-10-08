import HostXRayMonitor from "../components/HostXRayMonitor";

export default function TasksPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 font-sans">
      <HostXRayMonitor hostId="local" />
    </div>
  );
}

