"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";
import {
  LayoutDashboard,
  FileText,
  Server,
  Settings,
  LogOut,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarFooter,
} from "@/components/ui/sidebar";

const navItems = [
  { href: "/dashboard/home", label: "Dashboard", icon: LayoutDashboard },
  { href: "/dashboard/reports", label: "Reports", icon: FileText },
  { href: "/dashboard/benchmark", label: "Benchmark", icon: FileText },
  { href: "/dashboard/trails", label: "Audit Trails", icon: FileText },
  { href: "/dashboard/environments", label: "Environments", icon: Server },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
] as const;

export function DashboardSidebar() {
  const pathname = usePathname();

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="h-14 border-b border-sidebar-border">
        <Link href="/dashboard" className="flex items-center gap-2 px-2 py-2">
          <div className="flex items-center justify-center">
            <Image src="/brand/logo.png" alt="Logo" width={20} height={20} />
          </div>
          <span className="font-semibold text-sm group-data-[collapsible=icon]:hidden">
            NAZITEST
          </span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map(({ href, label, icon: Icon }) => (
                <SidebarMenuItem key={href}>
                  <SidebarMenuButton
                    asChild
                    isActive={
                      pathname === href || pathname.startsWith(href + "/")
                    }
                    // tooltip={label}
                  >
                    <Link href={href}>
                      <Icon className="size-4" />
                      <span>{label}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="border-t border-sidebar-border">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild>
              <a href="/auth/logout">
                <LogOut className="size-4" />
                <span>Logout</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
