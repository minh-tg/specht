import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export interface SelectOption {
  readonly value: string;
  readonly label: string;
  readonly disabled?: boolean;
}

/**
 * A single-choice dropdown built on the Base UI Select. It takes plain options and a string value
 * (the empty string is a real choice, for example "All severities"), so a call site reads like the
 * native element it replaces. Name it with `aria-label` or point a `<label htmlFor>` at `id`.
 */
export function SelectField({
  value,
  onValueChange,
  options,
  id,
  name,
  placeholder,
  disabled,
  required,
  size,
  className,
  "aria-label": ariaLabel,
  "aria-describedby": ariaDescribedBy,
}: {
  readonly value: string;
  readonly onValueChange: (value: string) => void;
  readonly options: readonly SelectOption[];
  readonly id?: string;
  readonly name?: string;
  readonly placeholder?: string;
  readonly disabled?: boolean;
  readonly required?: boolean;
  readonly size?: "sm" | "default";
  readonly className?: string;
  readonly "aria-label"?: string;
  readonly "aria-describedby"?: string;
}) {
  return (
    <Select
      value={value}
      onValueChange={(next) => onValueChange(next ?? "")}
      items={options}
      name={name}
      disabled={disabled}
      required={required}
    >
      <SelectTrigger
        id={id}
        size={size}
        className={className}
        aria-label={ariaLabel}
        aria-describedby={ariaDescribedBy}
      >
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent alignItemWithTrigger={false}>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value} disabled={o.disabled}>{o.label}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
