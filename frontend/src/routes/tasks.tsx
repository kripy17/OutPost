import { PageHeader } from "../components/ui";
import { EndpointTaskManager } from "../components/EndpointTaskManager";

export default function TasksPage() {
  return (
    <div className="mx-auto max-w-7xl px-5 py-8 lg:px-8 space-y-6">
      <PageHeader
        kicker="Endpoint Fleet · Real-Time Control"
        title="Live Task Manager & Process Explorer"
        lede="Inspect volatile system telemetry, CPU & memory utilization, listening network sockets, and active process trees in real time. Execute immediate containment actions including process termination (SIGTERM), hard kill (SIGKILL), process freezing (SIGSTOP), and live virtual memory YARA scans."
      />

      <EndpointTaskManager hostId="local" />
    </div>
  );
}
