/**
 * Phase 0 RUN-1 design-system showcase (TEMPORARY).
 * Validates Graphite Emerald tokens + shadcn primitives + theme + motion +
 * self-hosted fonts. RUN-2 replaces this with the real AppShell. Not imported
 * by App.jsx; rendered only by main.jsx for the foundation smoke target.
 */
import { motion } from "framer-motion"
import { toast } from "sonner"
import {
  Activity,
  Bell,
  Command,
  Fingerprint,
  ShieldCheck,
} from "lucide-react"

import { ThemeToggle } from "@/lib/theme"
import { useMotionVariants } from "@/lib/motion"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"

const SEVERITIES = [
  { label: "High", cls: "border-sev-high/30 bg-sev-high/15 text-sev-high" },
  { label: "Medium", cls: "border-sev-med/30 bg-sev-med/15 text-sev-med" },
  { label: "Low", cls: "border-sev-low/30 bg-sev-low/15 text-sev-low" },
  { label: "Speculative", cls: "border-sev-spec/30 bg-sev-spec/15 text-sev-spec" },
]

const STATUSES = [
  { label: "Approved", cls: "border-status-approved/30 bg-status-approved/15 text-status-approved" },
  { label: "Pending", cls: "border-status-pending/30 bg-status-pending/15 text-status-pending" },
  { label: "Staged", cls: "border-status-staged/30 bg-status-staged/15 text-status-staged" },
  { label: "Rejected", cls: "border-status-rejected/30 bg-status-rejected/15 text-status-rejected" },
]

const ROWS = [
  { id: "F-0001", sev: SEVERITIES[0], hash: "9f86d081884c7d65", ts: "2026-06-20T14:03:11Z" },
  { id: "F-0002", sev: SEVERITIES[1], hash: "2c26b46b68ffc68f", ts: "2026-06-20T14:07:42Z" },
  { id: "F-0003", sev: SEVERITIES[2], hash: "fcde2b2edba56bf4", ts: "2026-06-20T14:11:09Z" },
]

function Section({ title, children }) {
  return (
    <section className="space-y-4">
      <h2 className="text-lg font-semibold tracking-tight text-foreground">{title}</h2>
      {children}
    </section>
  )
}

export function Showcase() {
  const v = useMotionVariants()

  return (
    <motion.main
      variants={v.staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto max-w-5xl space-y-10 px-6 py-10"
    >
      {/* Header */}
      <motion.header
        variants={v.staggerItem}
        className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-6"
      >
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <ShieldCheck aria-hidden="true" className="size-5" />
          </span>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              Graphite Emerald — Design System
            </h1>
            <p className="text-sm text-muted-foreground">
              Phase 0 foundation smoke · Inter UI + Fira Code data
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2">
                <Command aria-hidden="true" className="size-4" />
                <span className="mono text-xs">⌘K</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent>Command palette (host added in RUN-2)</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon" aria-label="Notifications">
                <Bell aria-hidden="true" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Notifications</TooltipContent>
          </Tooltip>
          <ThemeToggle />
        </div>
      </motion.header>

      {/* Buttons */}
      <motion.div variants={v.staggerItem}>
        <Section title="Buttons">
          <div className="flex flex-wrap items-center gap-3">
            <Button>Primary</Button>
            <Button variant="secondary">Secondary</Button>
            <Button variant="outline">Outline</Button>
            <Button variant="ghost">Ghost</Button>
            <Button variant="destructive">Destructive</Button>
            <Button variant="link">Link</Button>
            <Button size="sm">Small</Button>
            <Button size="lg">Large</Button>
            <Button size="icon" aria-label="Activity">
              <Activity aria-hidden="true" />
            </Button>
          </div>
        </Section>
      </motion.div>

      {/* Badges */}
      <motion.div variants={v.staggerItem}>
        <Section title="Forensic badges">
          <div className="flex flex-wrap gap-2">
            {SEVERITIES.map((s) => (
              <Badge key={s.label} variant="outline" className={s.cls}>
                {s.label}
              </Badge>
            ))}
            {STATUSES.map((s) => (
              <Badge key={s.label} variant="outline" className={s.cls}>
                {s.label}
              </Badge>
            ))}
          </div>
        </Section>
      </motion.div>

      {/* Card with hover-lift + form */}
      <motion.div variants={v.staggerItem}>
        <Section title="Card · inputs · controls">
          <div className="grid gap-4 md:grid-cols-2">
            <motion.div variants={v.cardHover} initial="rest" whileHover="hover" className="h-full">
              <Card className="h-full transition-shadow hover:ring-2 hover:ring-ring/40">
                <CardHeader>
                  <CardTitle>Case integrity</CardTitle>
                  <CardDescription>Hover to lift (reduced-motion safe)</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1 text-sm">
                  <p className="text-muted-foreground">Chain status</p>
                  <p className="mono tnum text-status-approved">OK · sealed</p>
                </CardContent>
                <CardFooter>
                  <Badge variant="outline" className="border-status-approved/30 bg-status-approved/15 text-status-approved">
                    <Fingerprint aria-hidden="true" className="size-3" /> verified
                  </Badge>
                </CardFooter>
              </Card>
            </motion.div>

            <Card>
              <CardHeader>
                <CardTitle>Annotation</CardTitle>
                <CardDescription>Form primitives</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="case-id">Case ID</Label>
                  <Input id="case-id" defaultValue="case-rocba-3" className="mono" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="sev">Severity</Label>
                  <Select defaultValue="high">
                    <SelectTrigger id="sev">
                      <SelectValue placeholder="Select severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="med">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="note">Note</Label>
                  <Textarea id="note" placeholder="Examiner note…" />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="seal">Seal on save</Label>
                  <Switch id="seal" defaultChecked aria-label="Seal on save" />
                </div>
              </CardContent>
            </Card>
          </div>
        </Section>
      </motion.div>

      {/* Tabs + Table */}
      <motion.div variants={v.staggerItem}>
        <Section title="Tabs · table · mono data">
          <Tabs defaultValue="findings">
            <TabsList>
              <TabsTrigger value="findings">Findings</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
            </TabsList>
            <TabsContent value="findings" className="pt-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>SHA-256 (trunc)</TableHead>
                    <TableHead>Timestamp (UTC)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ROWS.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="mono">{r.id}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={r.sev.cls}>{r.sev.label}</Badge>
                      </TableCell>
                      <TableCell className="mono tnum text-muted-foreground">{r.hash}…</TableCell>
                      <TableCell className="mono tnum text-muted-foreground">{r.ts}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TabsContent>
            <TabsContent value="evidence" className="pt-4 text-sm text-muted-foreground">
              Evidence table arrives with AGENT-EVID in Phase 1.
            </TabsContent>
          </Tabs>
        </Section>
      </motion.div>

      {/* Feedback: alerts, progress, skeleton, dialogs, toast */}
      <motion.div variants={v.staggerItem}>
        <Section title="Feedback · overlays · loading">
          <div className="grid gap-4 md:grid-cols-2">
            <Alert>
              <ShieldCheck aria-hidden="true" />
              <AlertTitle>Evidence sealed</AlertTitle>
              <AlertDescription>Chain of custody intact for 3 artifacts.</AlertDescription>
            </Alert>
            <Alert variant="destructive">
              <Activity aria-hidden="true" />
              <AlertTitle>Hash mismatch</AlertTitle>
              <AlertDescription>Re-acquire artifact before continuing.</AlertDescription>
            </Alert>
          </div>

          <div className="space-y-2">
            <Label>Ingest progress</Label>
            <Progress value={62} />
          </div>

          <div className="space-y-2">
            <Label>Loading skeleton</Label>
            <div className="space-y-2">
              <Skeleton className="h-4 w-2/3" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-24 w-full" />
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="outline">Open dialog</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Commit staged changes</DialogTitle>
                  <DialogDescription>3 findings staged for this case.</DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <Button onClick={() => toast.success("Committed 3 findings")}>Commit</Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>

            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive">Destructive action</Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Unseal evidence?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This breaks the seal and is audit-logged. Confirm to proceed.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={() => toast.warning("Evidence unsealed")}>
                    Unseal
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>

            <Button variant="secondary" onClick={() => toast("Toast fired", { description: "Sonner is theme-aware." })}>
              Fire toast
            </Button>
          </div>
        </Section>
      </motion.div>

      {/* Motion stagger demo */}
      <motion.div variants={v.staggerItem}>
        <Section title="Staggered list (reduced-motion safe)">
          <motion.ul
            variants={v.staggerContainer}
            initial="hidden"
            animate="show"
            className="grid gap-2 sm:grid-cols-3"
          >
            {["acquire", "analyze", "attribute"].map((step) => (
              <motion.li
                key={step}
                variants={v.staggerItem}
                className="rounded-lg border border-border bg-card px-4 py-3 text-sm text-card-foreground"
              >
                <span className="mono text-xs text-muted-foreground">step</span>
                <div className="font-medium capitalize">{step}</div>
              </motion.li>
            ))}
          </motion.ul>
        </Section>
      </motion.div>
    </motion.main>
  )
}
