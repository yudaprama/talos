import type React from "react";
import Link from "@theme-original/DocSidebarItem/Link";
import type LinkType from "@theme/DocSidebarItem/Link";
import type { WrapperProps } from "@docusaurus/types";

type Props = WrapperProps<typeof LinkType>;

export default function LinkWrapper(props: Props): React.JSX.Element {
  const badge = props.item.customProps?.badge as string | undefined;

  if (!badge) {
    return <Link {...props} />;
  }

  // Add a CSS class to the item so we can render the badge via ::after.
  // Docusaurus applies item.className to the <a class="menu__link"> element.
  const item = {
    ...props.item,
    className: [props.item.className, "has-badge-commercial"].filter(Boolean).join(" "),
  };

  return <Link {...props} item={item} />;
}
