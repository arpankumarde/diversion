export interface Environment {
  id: string;
  name: string;
  target: string;
  repo: string;
}

/** Default environments for Start Scan dropdown. target = endpoint URL, repo = repository URL. */
export const DEFAULT_ENVIRONMENTS: Environment[] = [
  {
    id: "1",
    name: "dev-aws-1",
    target: "https://pentest-ground.com:4280",
    repo: "",
  },
  {
    id: "2",
    name: "staging-eu-1 (Juice Shop)",
    target: "https://juice.obvix.cloud",
    repo: "https://github.com/juice-shop/juice-shop",
  },
  {
    id: "3",
    name: "prod-us-east-1",
    target: "https://api.example.com/v1",
    repo: "",
  },
  {
    id: "4",
    name: "dev-local",
    target: "http://localhost:3000/api",
    repo: "",
  },
  {
    id: "5",
    name: "staging-aws-2",
    target: "https://api.staging-2.example.com/v1",
    repo: "",
  },
];
