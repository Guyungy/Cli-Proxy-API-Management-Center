import type { PropsWithChildren, ReactNode } from 'react';

interface CardProps {
  title?: ReactNode;
  extra?: ReactNode;
  className?: string;
}

export function Card({ title, extra, children, className }: PropsWithChildren<CardProps>) {
  return (
    <div className={className ? `card ${className}` : 'card'} data-slot="card">
      {(title || extra) && (
        <div className="card-header">
          <div className="title">{title}</div>
          {extra}
        </div>
      )}
      {children}
    </div>
  );
}
