"""
engine/pipeline.py — Sequential Pipeline + Parallel Dispatcher

Use:
  from engine.pipeline import Pipeline, ParallelDispatch
  pipeline = Pipeline()
  pipeline.add_stage("recon", recon_fn)
  pipeline.add_stage("hunt", hunt_fn, parallel=True)
  pipeline.add_stage("exploit", exploit_fn, parallel=True, max_concurrency=5)
  result = await pipeline.run(initial_state)
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

from loguru import logger


# ── Stage definition ─────────────────────────────────────────────────────────

@dataclass
class Stage:
    """A single pipeline stage."""
    name: str
    fn: Callable                    # async fn(state) -> state  OR  async fn(item) -> result
    parallel: bool = False          # if True, fn receives list and runs items in parallel
    max_concurrency: int = 5        # semaphore limit for parallel stages
    condition: Optional[Callable] = None  # fn(state) -> bool, skip stage if False
    # If fan_out is True, fn(state) must return a list of sub-tasks
    # and sub_fn processes each one
    fan_out: bool = False
    sub_fn: Optional[Callable] = None


# ── Pipeline ─────────────────────────────────────────────────────────────────

class Pipeline:
    """
    Sequential pipeline with optional parallel fan-out stages.

    State flows through each stage in order.
    Stages can fan-out to parallel sub-tasks.

    Example — 4-phase XLayer pipeline:
        pipeline = Pipeline()
        pipeline.add_stage("recon", recon_fn)
        pipeline.add_stage("hunt", hunt_fn)
        pipeline.add_stage("exploit", exploit_fn, fan_out=True,
                           sub_fn=solver_fn, max_concurrency=5)
        pipeline.add_stage("report", report_fn)
        final_state = await pipeline.run({"url": "https://target.com"})
    """

    def __init__(self) -> None:
        self._stages: List[Stage] = []

    def add_stage(
        self,
        name: str,
        fn: Callable,
        *,
        parallel: bool = False,
        fan_out: bool = False,
        sub_fn: Optional[Callable] = None,
        max_concurrency: int = 5,
        condition: Optional[Callable] = None,
    ) -> "Pipeline":
        """Add a stage to the pipeline. Returns self for chaining."""
        self._stages.append(Stage(
            name=name,
            fn=fn,
            parallel=parallel,
            fan_out=fan_out,
            sub_fn=sub_fn,
            max_concurrency=max_concurrency,
            condition=condition,
        ))
        return self

    async def run(self, initial_state: Any) -> Any:
        """
        Execute all stages sequentially, passing state from one to the next.
        """
        state = initial_state

        for stage in self._stages:
            # Condition check — skip if returns False
            if stage.condition is not None:
                try:
                    if not stage.condition(state):
                        logger.debug(f"[Pipeline] Skipping stage '{stage.name}' (condition=False)")
                        continue
                except Exception as e:
                    logger.warning(f"[Pipeline] Condition check failed for '{stage.name}': {e}")
                    continue

            logger.info(f"[Pipeline] Running stage: {stage.name}")

            try:
                if stage.fan_out and stage.sub_fn:
                    # fan_out: fn(state) returns list of tasks, sub_fn processes each
                    tasks = await stage.fn(state)
                    if tasks:
                        results = await ParallelDispatch.run(
                            stage.sub_fn, tasks, max_concurrency=stage.max_concurrency
                        )
                        state = _merge_fan_out_results(state, results, stage.name)
                    else:
                        logger.debug(f"[Pipeline] Stage '{stage.name}' produced no tasks")
                else:
                    # Normal stage: fn(state) -> new state
                    state = await stage.fn(state)

            except Exception as e:
                logger.error(f"[Pipeline] Stage '{stage.name}' failed: {e}")
                # Continue pipeline — failed stage doesn't abort everything
                # (caller can check state for errors)

        return state


def _merge_fan_out_results(
    state: Any, results: List[Any], stage_name: str
) -> Any:
    """
    Merge fan-out sub-task results back into state.
    If state is a dict, results are stored under key `f"{stage_name}_results"`.
    """
    if isinstance(state, dict):
        state[f"{stage_name}_results"] = results
        return state
    # For dataclass/object states, try setting attribute
    try:
        setattr(state, f"{stage_name}_results", results)
    except Exception:
        pass
    return state


# ── ParallelDispatch ─────────────────────────────────────────────────────────

class ParallelDispatch:
    """
    Run an async function over a list of tasks in parallel,
    bounded by a semaphore.

    Example:
      results = await ParallelDispatch.run(solver_fn, tasks, max_concurrency=5)
    """

    @staticmethod
    async def run(
        fn: Callable,
        tasks: List[Any],
        max_concurrency: int = 5,
        return_exceptions: bool = True,
    ) -> List[Any]:
        """
        Execute fn(task) for each task in parallel, up to max_concurrency at once.

        Args:
            fn: Async function to call for each task
            tasks: List of task arguments (each is passed as fn(task))
            max_concurrency: Max simultaneous executions
            return_exceptions: If True, exceptions are returned as values not raised

        Returns:
            List of results in same order as tasks
        """
        if not tasks:
            return []

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _run_one(task: Any, idx: int) -> Any:
            async with semaphore:
                logger.debug(f"[ParallelDispatch] Starting task {idx+1}/{len(tasks)}")
                try:
                    result = await fn(task)
                    logger.debug(f"[ParallelDispatch] Task {idx+1} done")
                    return result
                except Exception as e:
                    logger.error(f"[ParallelDispatch] Task {idx+1} failed: {e}")
                    if return_exceptions:
                        return e
                    raise

        coroutines = [_run_one(task, i) for i, task in enumerate(tasks)]
        results = await asyncio.gather(*coroutines, return_exceptions=return_exceptions)
        return list(results)

    @staticmethod
    async def run_with_timeout(
        fn: Callable,
        tasks: List[Any],
        max_concurrency: int = 5,
        timeout_per_task: float = 300.0,
    ) -> List[Any]:
        """
        Like run() but each task has an individual timeout.
        Timed-out tasks return a TimeoutError in the results list.
        """
        async def _with_timeout(task: Any) -> Any:
            return await asyncio.wait_for(fn(task), timeout=timeout_per_task)

        return await ParallelDispatch.run(
            _with_timeout, tasks, max_concurrency=max_concurrency
        )
