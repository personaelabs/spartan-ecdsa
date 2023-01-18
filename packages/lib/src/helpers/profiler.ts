export class Profiler {
  private enabled: boolean;

  constructor(options: { enabled?: boolean }) {
    this.enabled = options.enabled || false;
  }

  time(label: string) {
    this.enabled && console.time(label);
  }

  timeEnd(label: string) {
    this.enabled && console.timeEnd(label);
  }
}
