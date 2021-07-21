use scheduler_client::{
    register, schedule_one_of, ResourceAlloc, ResourceMemory, ResourceReq, ResourceType, TaskFunc,
    TaskReqBuilder, TaskResult, TaskType,
};
use std::time::Duration;
use storage_proofs_core::error::{Error, Result};

// TODO: We need to define if this is going to be part of the configuration file
// as well as an appropiate value for this.
const TIMEOUT: u64 = 1200;

pub(crate) struct Builder<F>
where
    for<'a> F: FnMut(Option<&'a ResourceAlloc>) -> Result<TaskResult, Error>,
{
    call: F,
    num_iter: usize,
    name: Option<String>,
    context: Option<String>,
}

impl<F> Builder<F>
where
    for<'a> F: FnMut(Option<&'a ResourceAlloc>) -> Result<TaskResult, Error>,
{
    pub(crate) fn new(
        call: F,
        num_iter: usize,
        client_name: Option<String>,
        context: Option<String>,
    ) -> Self {
        Self {
            call,
            num_iter,
            name: client_name,
            context,
        }
    }

    pub(crate) fn build(&mut self) -> Result<(), Error> {
        let requirements = {
            let resouce_req = ResourceReq {
                resource: ResourceType::Gpu(ResourceMemory::All),
                quantity: 1,
                preemptible: self.num_iter > 1,
            };
            let task_req = TaskReqBuilder::new()
                .with_task_type(TaskType::MerkleProof)
                .resource_req(resouce_req);
            task_req.build()
        };
        let client = register::<Error>(self.name.take(), self.context.take())?;

        schedule_one_of(client, self, requirements, Duration::from_secs(TIMEOUT)).map(|_| ())
    }
}

impl<F> TaskFunc for Builder<F>
where
    for<'a> F: FnMut(Option<&'a ResourceAlloc>) -> Result<TaskResult, Error>,
{
    type Output = ();
    type Error = Error;

    fn init(&mut self, _alloc: Option<&ResourceAlloc>) -> Result<Self::Output, Self::Error> {
        Ok(())
    }
    fn end(&mut self, _: Option<&ResourceAlloc>) -> Result<Self::Output, Self::Error> {
        Ok(())
    }

    fn task(&mut self, alloc: Option<&ResourceAlloc>) -> Result<TaskResult, Self::Error> {
        (self.call)(alloc)
    }
}
