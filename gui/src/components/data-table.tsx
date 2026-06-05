// Generic data table over TanStack Table: sortable headers, quick-search,
// client-side pagination with a page-size picker. Headless core, styled to
// match the app's dense-table look (see Vaults). Server-side concerns (date
// range, structured filters) stay in the screen; this handles the grid.

import { ReactNode, useState } from "react";
import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { Button, Input, Select } from "./ui";

const PAGE_SIZES = [25, 50, 100, 250];

export function DataTable<T>({
  columns,
  data,
  searchPlaceholder = "Search…",
  initialSort = [],
  emptyMessage = "No rows.",
}: {
  columns: ColumnDef<T, any>[];
  data: T[];
  searchPlaceholder?: string;
  initialSort?: SortingState;
  emptyMessage?: string;
}) {
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const [globalFilter, setGlobalFilter] = useState("");

  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: "includesString",
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 50 } },
  });

  const total = table.getFilteredRowModel().rows.length;
  const { pageIndex, pageSize } = table.getState().pagination;
  const pageCount = table.getPageCount();

  return (
    <div className="flex flex-col gap-3">
      <Input
        placeholder={searchPlaceholder}
        value={globalFilter}
        onChange={(e) => setGlobalFilter(e.target.value)}
        className="w-64"
      />

      {total === 0 ? (
        <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
          {emptyMessage}
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-border-subtle">
          <table className="w-full text-sm">
            <thead className="bg-surface-sunken text-left text-xs uppercase text-content-muted">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((h) => (
                    <th key={h.id} className="px-3 py-2 font-medium">
                      {h.isPlaceholder ? null : h.column.getCanSort() ? (
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 uppercase hover:text-content"
                          onClick={h.column.getToggleSortingHandler()}
                        >
                          {flexRender(h.column.columnDef.header, h.getContext())}
                          <span className="text-[10px]">
                            {{ asc: "▲", desc: "▼" }[
                              h.column.getIsSorted() as string
                            ] ?? ""}
                          </span>
                        </button>
                      ) : (
                        flexRender(h.column.columnDef.header, h.getContext())
                      )}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="border-t border-border-subtle hover:bg-surface-raised/40"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-3 py-2 align-middle">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {total > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-content-muted">
          <span>
            {total} row{total === 1 ? "" : "s"}
          </span>
          <span className="mx-1">·</span>
          <Select
            className="h-7 w-20 px-2 py-0 text-xs"
            value={String(pageSize)}
            onChange={(e) => table.setPageSize(Number(e.target.value))}
          >
            {PAGE_SIZES.map((s) => (
              <option key={s} value={s}>
                {s} / pg
              </option>
            ))}
          </Select>
          <div className="ml-auto flex items-center gap-1">
            <PagerBtn
              disabled={!table.getCanPreviousPage()}
              onClick={() => table.firstPage()}
            >
              «
            </PagerBtn>
            <PagerBtn
              disabled={!table.getCanPreviousPage()}
              onClick={() => table.previousPage()}
            >
              ‹
            </PagerBtn>
            <span className="px-2">
              page {pageIndex + 1} / {Math.max(pageCount, 1)}
            </span>
            <PagerBtn
              disabled={!table.getCanNextPage()}
              onClick={() => table.nextPage()}
            >
              ›
            </PagerBtn>
            <PagerBtn
              disabled={!table.getCanNextPage()}
              onClick={() => table.lastPage()}
            >
              »
            </PagerBtn>
          </div>
        </div>
      )}
    </div>
  );
}

function PagerBtn({
  children,
  disabled,
  onClick,
}: {
  children: ReactNode;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      variant="secondary"
      className="h-7 px-2 py-0 text-xs"
      disabled={disabled}
      onClick={onClick}
    >
      {children}
    </Button>
  );
}
